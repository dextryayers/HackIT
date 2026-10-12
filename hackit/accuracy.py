"""
HackIT Phase 1 shared accuracy engine v2.1 Pro.
Real production code, no simulation.
Covers adaptive concurrency, HTTP calibration, response comparator,
timing calibration, dedup, voting, and redaction.
"""
import hashlib
import re
import statistics
import time

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical", "candidate")

ENGINE_WEIGHTS = {"go": 0.50, "python": 0.30, "rust": 0.15, "c": 0.05}

SENSITIVE_KEYS = ("authorization", "cookie", "set-cookie", "password", "passwd", "token", "api_key", "apikey", "secret")


class AdaptiveController:
    """Real token bucket with timeout-driven adjustment."""

    def __init__(self, initial=50, minimum=2, maximum=200):
        self.limit = int(initial)
        self.minimum = int(minimum)
        self.maximum = int(maximum)
        self.window = []
        self.last_upshift_ms = int(time.time() * 1000)

    def observe(self, timed_out, total):
        now = int(time.time() * 1000)
        self.window.append((now, bool(timed_out), int(total)))
        cutoff = now - 5000
        self.window = [w for w in self.window if w[0] >= cutoff]
        if not self.window:
            return self.limit
        timeouts = sum(1 for _, t, _ in self.window if t)
        rate = timeouts / len(self.window)
        if rate > 0.10:
            self.limit = max(self.minimum, self.limit // 2)
            self.window = []
            return self.limit
        if rate < 0.02 and now - self.last_upshift_ms >= 10000:
            self.limit = min(self.maximum, int(self.limit * 1.25) or 1)
            self.last_upshift_ms = now
            self.window = []
        return self.limit

    def jitter_ms(self, base_ms=0):
        import random
        if self.limit <= 5:
            return base_ms + random.randint(100, 400)
        return base_ms


def target_hash(value):
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:8]


def normalize_body(body):
    if not body:
        return ""
    text = body
    text = re.sub(r"[0-9a-fA-F]{16,}", "HEX", text)
    text = re.sub(r"\d+", "N", text)
    text = re.sub(r"(csrf|nonce|timestamp|_token|request_id)[^,;\"']*", "DYN", text, flags=re.IGNORECASE)
    return text.strip()


def struct_hash(body):
    norm = normalize_body(body)
    return hashlib.sha256(norm.encode("utf-8", errors="ignore")).hexdigest()[:16]


def calibrate_http(samples):
    """Build a real baseline from measured samples.

    samples: list of dicts with status, body, elapsed_ms.
    Returns baseline dict with status_mode, len_median, struct_hash_mode, p50_ms, stddev_ms.
    """
    if not samples:
        raise ValueError("empty calibration samples")
    statuses = [s.get("status", 0) for s in samples]
    status_mode = max(set(statuses), key=statuses.count)
    lengths = sorted(len(s.get("body", "") or "") for s in samples)
    mid = len(lengths) // 2
    len_median = lengths[mid] if lengths else 0
    hashes = [struct_hash(s.get("body", "") or "") for s in samples]
    struct_mode = max(set(hashes), key=hashes.count)
    lat = sorted(float(s.get("elapsed_ms", 0)) for s in samples)
    p50 = lat[len(lat) // 2] if lat else 0.0
    stddev = statistics.pstdev(lat) if len(lat) > 1 else 0.0
    return {
        "status_mode": status_mode,
        "len_median": len_median,
        "struct_hash_mode": struct_mode,
        "p50_ms": round(p50, 2),
        "stddev_ms": round(stddev, 2),
        "sample_count": len(samples),
    }


def compare_resp(candidate, baseline):
    """Compare a candidate response against a calibrated baseline.

    Returns dict with verdict in same, soft_diff, hard_diff plus score and reason.
    Weights: structure 0.50, length 0.20, headers 0.20, status 0.10.
    """
    cand_struct = struct_hash(candidate.get("body", "") or "")
    base_struct = baseline.get("struct_hash_mode", "")
    struct_score = 1.0 if cand_struct == base_struct else 0.0

    cand_len = len(candidate.get("body", "") or "")
    base_len = baseline.get("len_median", 0) or 1
    len_diff = abs(cand_len - base_len) / max(base_len, 1)
    len_score = 1.0 if len_diff < 0.05 else (0.5 if len_diff < 0.25 else 0.0)

    cand_headers = candidate.get("headers", {}) or {}
    base_headers = baseline.get("headers", {}) or {}
    key_headers = ("content-type", "location", "www-authenticate")
    header_match = sum(1 for k in key_headers if str(cand_headers.get(k, "")) == str(base_headers.get(k, "")))
    header_score = header_match / len(key_headers)

    status_score = 1.0 if candidate.get("status") == baseline.get("status_mode") else 0.0

    total = 0.50 * struct_score + 0.20 * len_score + 0.20 * header_score + 0.10 * status_score
    if total >= 0.92:
        verdict = "same"
    elif total >= 0.60:
        verdict = "soft_diff"
    else:
        verdict = "hard_diff"
    return {
        "verdict": verdict,
        "score": round(total, 3),
        "reason": "struct=%s len_diff=%.3f headers=%d/3 status=%s" % (cand_struct[:8], len_diff, header_match, status_score == 1.0),
    }


def calibrate_timing(normal_ms_list):
    """Build a real sleep threshold from measured normal latencies."""
    if len(normal_ms_list) < 3:
        raise ValueError("need at least 3 timing samples")
    ordered = sorted(float(x) for x in normal_ms_list)
    p50 = ordered[len(ordered) // 2]
    stddev = statistics.pstdev(ordered) if len(ordered) > 1 else 0.0
    threshold = p50 + 4000.0
    unstable = stddev > 800.0
    return {
        "p50_ms": round(p50, 2),
        "stddev_ms": round(stddev, 2),
        "threshold_ms": round(threshold, 2),
        "unstable_network": bool(unstable),
        "max_confidence": 0.69 if unstable else 0.95,
    }


def dedup_key(module, target, vuln_class, param, proof):
    raw = "%s|%s|%s|%s|%s" % (module, target_hash(target), vuln_class, param, hashlib.sha256(proof.encode("utf-8", errors="ignore")).hexdigest()[:12])
    return raw


def merge_confidence(base, independent_sources=1, single_weak=False):
    score = float(base)
    if independent_sources >= 2:
        score += 0.05
    if single_weak:
        score -= 0.15
    return round(max(0.0, min(0.98, score)), 3)


def engine_vote(findings):
    """Weighted vote across engines. Each finding needs engine and confidence."""
    total_w = 0.0
    total_s = 0.0
    for f in findings:
        w = ENGINE_WEIGHTS.get(str(f.get("engine", "python")).lower(), 0.10)
        total_w += w
        total_s += w * float(f.get("confidence", 0.0))
    if total_w == 0:
        return 0.0
    return round(total_s / total_w, 3)


def redact_text(text):
    if not text:
        return ""
    out = str(text)
    for key in SENSITIVE_KEYS:
        out = re.sub(r"(?i)(%s\s*[:=]\s*)([^\s;,\"']+)" % re.escape(key), r"\1***", out)
    out = re.sub(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+", "Bearer ***", out)
    return out[:2000]


def confidence_label(confidence):
    c = float(confidence)
    if c >= 0.90:
        return "confirmed"
    if c >= 0.70:
        return "strong"
    if c >= 0.60:
        return "moderate"
    return "candidate"
