"""Scope enforcement for authorized resilience testing.

Fail-closed by design: any missing field, mismatch, or expired scope
aborts before an engine is ever launched. The scope file is the written
permission; the CLI is just the enforcement point.

L7 (request) and L4 (packet) engines have different ceilings, so the scope
carries them separately: `max_rps` gates HTTP-family profiles, `max_pps`
gates raw-packet profiles. A single shared cap would either strangle the
packet engines or let an HTTP run overrun its ceiling.

Profiles are grouped by the ceiling family they are actually bound by:
  L4 (packets/s)  syn ack rst fin psh xmas null udp-flood icmp-flood
  L7 (requests/s) http https http-raw tcp dns udp ws slowloris

A run may name several profiles at once; it is bound by the strictest family
present, so `--profile syn,http` is gated by `max_pps`.

Scope file format (JSON):

{
  "operator": "Hanif",
  "approval_ref": "CHG-1234",
  "targets": ["staging.example.internal", "10.0.0.0/24", "*.lab.example"],
  "max_rps": 500,
  "max_pps": 200000,
  "max_workers": 64,
  "max_duration_s": 120,
  "expires": "2026-12-31T23:59:59Z",
  "authorized": true
}

`max_pps` may be omitted; it then defaults to the hard ceiling.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, List, Sequence, Union

__all__ = [
    "ALL_PROFILES",
    "ENGINE_L4",
    "ENGINE_L7",
    "EffectiveLimits",
    "HARD_MAX_DURATION_S",
    "HARD_MAX_PPS",
    "HARD_MAX_RPS",
    "HARD_MAX_WORKERS",
    "L4_PROFILES",
    "L7_PROFILES",
    "Scope",
    "ScopeError",
    "check_run",
    "effective_limits",
    "engine_kind",
    "is_l4",
    "load_scope",
    "validate_profiles",
]

HARD_MAX_RPS = 20000          # L7: requests/second
HARD_MAX_PPS = 1000000        # L4: packets/second
HARD_MAX_WORKERS = 512
HARD_MAX_DURATION_S = 1200

ENGINE_L4 = "l4"
ENGINE_L7 = "l7"

# Raw-packet profiles. Gated by max_pps, need root/CAP_NET_RAW.
L4_PROFILES = frozenset({
    "syn", "ack", "rst", "fin", "psh", "xmas", "null",
    "udp-flood", "icmp-flood",
})

# Request/connection profiles. Gated by max_rps.
L7_PROFILES = frozenset({
    "http", "https", "http-raw", "tcp", "dns", "udp", "ws", "slowloris",
})

ALL_PROFILES = frozenset(L4_PROFILES | L7_PROFILES)

_ISO_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[T ]"
    r"(?P<h>\d{2}):(?P<m>\d{2})(?::(?P<s>\d{2}))?(?P<frac>\.\d+)?"
    r"(?P<off>Z|z|[+-]\d{2}:?\d{2})?$"
)
_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?$")


class ScopeError(Exception):
    """Raised when scope validation fails. Never caught to 'try anyway'."""


def is_l4(profile: str) -> bool:
    """True when the profile is a raw-packet vector bound by max_pps."""
    return profile.strip().lower() in L4_PROFILES


def engine_kind(profile: str) -> str:
    """Map a profile to the ceiling family it is actually bound by."""
    return ENGINE_L4 if is_l4(profile) else ENGINE_L7


def validate_profiles(profiles: Union[str, Iterable[str]]) -> List[str]:
    """Normalise a profile spec and reject unknown names before any load."""
    if isinstance(profiles, str):
        items = [p for p in profiles.split(",")]
    else:
        items = list(profiles)
    out: List[str] = []
    unknown: List[str] = []
    for item in items:
        p = item.strip().lower()
        if not p:
            continue
        if p not in ALL_PROFILES:
            unknown.append(p)
        elif p not in out:
            out.append(p)
    if unknown:
        raise ScopeError(f"unknown profile(s): {', '.join(sorted(set(unknown)))}")
    if not out:
        raise ScopeError("at least one profile is required")
    return out


@dataclass(frozen=True)
class Scope:
    operator: str
    approval_ref: str
    targets: List[str]
    max_rps: int
    max_pps: int
    max_workers: int
    max_duration_s: int
    expires: datetime

    def allows(self, host: str) -> bool:
        host = host.strip().lower().rstrip(".")
        if not host:
            return False
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        for entry in self.targets:
            entry = entry.strip().lower()
            if not entry:
                continue
            if entry == "*":
                return True
            if entry.startswith("*."):
                # *.lab.example allows a.lab.example AND lab.example itself:
                # an operator writing the wildcard means the zone, not only
                # its leaves.
                suffix = entry[1:]          # ".lab.example"
                if host == entry[2:] or host.endswith(suffix):
                    return True
                continue
            if ip is not None:
                try:
                    if ip in ipaddress.ip_network(entry, strict=False):
                        return True
                    continue
                except ValueError:
                    pass
            if host == entry:
                return True
        return False


@dataclass(frozen=True)
class EffectiveLimits:
    rate: int
    workers: int
    duration_s: int


def _parse_expires(raw: Any) -> datetime:
    if not isinstance(raw, str):
        raise ScopeError("scope 'expires' must be an ISO 8601 string, e.g. 2026-12-31T23:59:59Z")
    m = _ISO_RE.match(raw.strip())
    if not m:
        raise ScopeError("scope 'expires' must be ISO 8601, e.g. 2026-12-31T23:59:59Z")

    off = m.group("off") or "+00:00"
    if off in ("Z", "z"):
        off = "+00:00"
    elif ":" not in off:                 # +0700 -> +07:00
        off = f"{off[:3]}:{off[3:]}"

    text = "{date}T{h}:{mi}:{s}{frac}{off}".format(
        date=m.group("date"), h=m.group("h"), mi=m.group("m"),
        s=m.group("s") or "00", frac=m.group("frac") or "", off=off,
    )
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ScopeError(f"scope 'expires' is not parseable: {exc}") from exc
    return dt.astimezone(timezone.utc)


def _require_int(data: dict, key: str, lo: int, hi: int, *, default: int | None = None) -> int:
    value = data.get(key, default)
    if value is None:
        raise ScopeError(f"scope '{key}' is required")
    if not isinstance(value, int) or isinstance(value, bool):
        raise ScopeError(f"scope '{key}' must be an integer")
    if value < lo:
        raise ScopeError(f"scope '{key}' must be >= {lo}")
    return min(value, hi)


def _validate_targets(targets: Sequence[str]) -> None:
    """Reject inert entries at load time instead of silently never matching."""
    for entry in targets:
        e = entry.strip().lower().rstrip(".")
        if not e:
            raise ScopeError("scope 'targets' contains an empty entry")
        if e == "*" or e.startswith("*."):
            if e.startswith("*.") and len(e) < 4:
                raise ScopeError(f"scope target '{entry}' is a wildcard with no zone")
            continue
        if "/" in e:
            try:
                ipaddress.ip_network(e, strict=False)
                continue
            except ValueError as exc:
                raise ScopeError(f"scope target '{entry}' is not a valid CIDR: {exc}") from exc
        try:
            ipaddress.ip_address(e)
            continue
        except ValueError:
            pass
        if not _HOSTNAME_RE.match(e):
            raise ScopeError(f"scope target '{entry}' is not a hostname, IP, CIDR or wildcard")


def load_scope(path: str) -> Scope:
    scope_path = Path(path)
    if not scope_path.is_file():
        raise ScopeError(f"scope file not found: {path}")
    try:
        data = json.loads(scope_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ScopeError(f"scope file is not valid JSON: {exc}") from exc
    except OSError as exc:
        raise ScopeError(f"scope file cannot be read: {exc}") from exc
    if not isinstance(data, dict):
        raise ScopeError("scope file must contain a JSON object")

    if data.get("authorized") is not True:
        raise ScopeError("scope 'authorized' must be true — this run needs written approval")

    operator = data.get("operator")
    if not isinstance(operator, str) or not operator.strip():
        raise ScopeError("scope 'operator' must be a non-empty string")

    approval_ref = data.get("approval_ref")
    if not isinstance(approval_ref, str) or not approval_ref.strip():
        raise ScopeError("scope 'approval_ref' must be a non-empty string (ticket/CHG ref)")

    targets = data.get("targets")
    if not isinstance(targets, list) or not targets or not all(
            isinstance(t, str) and t.strip() for t in targets):
        raise ScopeError("scope 'targets' must be a non-empty list of hosts, CIDRs or *.suffix entries")
    _validate_targets(targets)

    expires = _parse_expires(data.get("expires"))
    now = datetime.now(timezone.utc)
    if expires <= now:
        raise ScopeError(f"scope expired at {expires.isoformat()} — get it renewed before testing")

    max_rps = _require_int(data, "max_rps", 1, HARD_MAX_RPS)
    max_pps = _require_int(data, "max_pps", 1, HARD_MAX_PPS, default=HARD_MAX_PPS)
    max_workers = _require_int(data, "max_workers", 1, HARD_MAX_WORKERS)
    max_duration_s = _require_int(data, "max_duration_s", 1, HARD_MAX_DURATION_S)

    return Scope(
        operator=operator.strip(),
        approval_ref=approval_ref.strip(),
        targets=[t.strip() for t in targets],
        max_rps=max_rps,
        max_pps=max_pps,
        max_workers=max_workers,
        max_duration_s=max_duration_s,
        expires=expires,
    )


def effective_limits(scope: Scope, profiles: Union[str, Iterable[str]],
                     rate: int, workers: int, duration_s: int) -> EffectiveLimits:
    """Clamp a requested run to the scope and the hard ceilings.

    `profiles` may be a single name or a list. When any L4 profile is present
    the run is gated by max_pps, otherwise by max_rps: a mixed run saturates
    the packet path first, so the packet ceiling is the honest one.
    """
    if rate < 1:
        raise ScopeError("--rps must be >= 1")
    if workers < 1:
        raise ScopeError("--workers must be >= 1")
    if duration_s < 1:
        raise ScopeError("--duration must be >= 1 second")

    names = validate_profiles(profiles)
    if any(is_l4(p) for p in names):
        capped = min(rate, scope.max_pps, HARD_MAX_PPS)
    else:
        capped = min(rate, scope.max_rps, HARD_MAX_RPS)

    return EffectiveLimits(
        rate=capped,
        workers=min(workers, scope.max_workers, HARD_MAX_WORKERS),
        duration_s=min(duration_s, scope.max_duration_s, HARD_MAX_DURATION_S),
    )


def check_run(scope: Scope, host: str, approval: str) -> None:
    """Gate every run. Raises ScopeError on any mismatch."""
    if approval != scope.approval_ref:
        raise ScopeError("--approval does not match scope 'approval_ref' — refusing to run")
    if not scope.allows(host):
        raise ScopeError(f"target '{host}' is not in the scope allowlist — refusing to run")