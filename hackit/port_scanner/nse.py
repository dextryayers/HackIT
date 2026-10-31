"""Unified NSE engine — real nmap-backed execution of the bundled script set.

The bundled ``hackit/nse_scripts`` tree is a stock NSE corpus. Rather than
re-implementing the NSE API, this module delegates execution to ``nmap``'s own
script engine, which is the only implementation that can honour ``portrule``,
``hostrule``, ``--script-args`` and the full ``nse_*`` library surface.

Public surface
--------------
``NseEngine``
    Discovery (``scripts``, ``categories``, ``select``) plus execution
    (``run``, ``run_for_ports``).
``ScriptInfo`` / ``ScriptResult``
    Immutable records shared by the CLI and the GUI.
``SEVERITY_ORDER``
    Ordering used by both front-ends when sorting findings.

Execution model
---------------
One ``nmap`` process per port batch, with every selected script attached. nmap
applies each script's own ``portrule`` so a script only runs where it can
actually do something. Banners come back as structured XML, not scraped text.

The engine never fabricates output: a script that did not run produces no
result, and a script that errored produces a result flagged with ``error``.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent.parent / "nse_scripts"

SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

# Category descriptions surfaced in the CLI and GUI pickers.
CATEGORY_LABELS = {
    "audit": "Configuration audit checks",
    "auth": "Authentication checks",
    "broadcast": "Broadcast / LAN discovery",
    "brute": "Credential brute force",
    "cloud": "Cloud metadata / storage",
    "database": "Database service probes",
    "default": "Default safe set",
    "discovery": "Service and host discovery",
    "dos": "Denial-of-service probes",
    "exploit": "Active exploitation",
    "external": "Third-party data sources",
    "fuzzer": "Protocol fuzzers",
    "intrusive": "Intrusive probes",
    "iot": "IoT device probes",
    "malware": "Malware / backdoor detection",
    "safe": "Non-disruptive checks",
    "version": "Version detection helpers",
    "voip": "VoIP service probes",
    "vuln": "Vulnerability detection",
    "web": "Web application checks",
}

# Ordered strongest-first. First match wins.
_SEVERITY_RULES: Tuple[Tuple[str, str], ...] = (
    (r"\bCRITICAL\b", "critical"),
    (r"(?<!not )\bVULNERABLE\b", "high"),
    (r"\bdefault (?:credential|password|login)s?\b", "high"),
    (r"\banonymous (?:login|bind|access)\b.*\b(?:allowed|enabled|success)", "high"),
    (r"\b(?:no|missing|weak) (?:auth|authentication|encryption)\b", "medium"),
    (r"\b(?:outdated|end[- ]of[- ]life|deprecated)\b", "medium"),
    (r"\b(?:exposed|discloses?|leak(?:s|ed)?|enumeration)\b", "medium"),
)

# A script that checked for something and did not find it is not a finding.
# These read first: "No Struts2 devMode detected" must never score high just
# because the output also names the CVE it was testing for.
_NEGATIVE_RE = re.compile(
    r"(?:"
    r"\bnot (?:vulnerable|affected|exposed|present|detected|supported|enabled)\b"
    r"|\bno\s+[\w./ -]{0,48}?(?:detected|found|vulnerabilit\w*|exposure|issues?)\b"
    r"|\bdoes not (?:appear|support|allow|seem)\b"
    r"|\bdoesn't (?:appear|support|allow|seem)\b"
    r"|\b(?:couldn't|could not) (?:find|detect|connect|retrieve)\b"
    r"|\bno evidence\b"
    r"|\bnot running\b"
    r"|\bvulnerable\s*[:=]\s*false\b"
    r"|\bseverity\s*[:=]\s*(?:none|info|low)\b"
    r")",
    re.I,
)
_NEGATIVE_OVERRIDE_RE = re.compile(
    r"\b(?:CRITICAL|VULNERABLE)\b(?!\s*[:=]\s*(?:false|no)\b)", re.I)

_TAG_RE = re.compile(r"<[^>]+>")


@dataclass(frozen=True)
class ScriptInfo:
    """Static description of one bundled NSE script."""

    name: str
    path: Path
    description: str
    author: str
    categories: Tuple[str, ...]
    has_hostrule: bool
    has_portrule: bool
    explicit_ports: Tuple[int, ...]

    @property
    def short_description(self) -> str:
        text = " ".join(self.description.split())
        if len(text) <= 110:
            return text
        return text[:107].rstrip() + "..."

    @property
    def primary_category(self) -> str:
        for preferred in ("vuln", "exploit", "brute", "auth", "malware",
                          "discovery", "dos", "safe", "default"):
            if preferred in self.categories:
                return preferred
        return self.categories[0] if self.categories else "default"

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "description": self.description,
            "author": self.author,
            "categories": list(self.categories),
            "primary_category": self.primary_category,
            "explicit_ports": list(self.explicit_ports),
            "has_hostrule": self.has_hostrule,
            "has_portrule": self.has_portrule,
        }


@dataclass
class ScriptResult:
    """Outcome of one script against one port (or the host)."""

    script: str
    port: int
    protocol: str
    output: List[str]
    severity: str = "info"
    elapsed: float = 0.0
    error: Optional[str] = None
    categories: Tuple[str, ...] = ()

    @property
    def summary(self) -> str:
        if self.error:
            return "error: " + self.error
        return " ".join(self.output)[:160]

    @property
    def text(self) -> str:
        return "\n".join(self.output)

    def to_dict(self) -> Dict[str, object]:
        return {
            "script": self.script,
            "port": self.port,
            "protocol": self.protocol,
            "output": list(self.output),
            "severity": self.severity,
            "elapsed": round(self.elapsed, 3),
            "error": self.error,
            "categories": list(self.categories),
        }


# ─────────────────────────────────────────────────────────────────
# DISCOVERY
# ─────────────────────────────────────────────────────────────────

_LONG_BRACKET = re.compile(r"\[(=*)\[(.*?)\]\1\]", re.S)
_AUTHOR = re.compile(r'^\s*author\s*=\s*"([^"]*)"', re.M)
_CATEGORIES = re.compile(r"^\s*categories\s*=\s*\{([^}]*)\}", re.M)
_HAS_HOSTRULE = re.compile(r"\bhostrule\s*[,=]", re.M)
_HAS_PORTRULE = re.compile(r"\bportrule\s*[,=]", re.M)
_HAS_PRERULE = re.compile(r"\bprerule\s*[,=]", re.M)
_PORT_LIST = re.compile(r"port(?:_or_service|number)?\s*\(\s*\{([0-9,\s\-]+)\}")
_PORT_EQ = re.compile(r"port\.number\s*==\s*(\d{1,5})")


def _parse_metadata(path: Path) -> Optional[ScriptInfo]:
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    if not (_HAS_HOSTRULE.search(source) or _HAS_PORTRULE.search(source)
            or _HAS_PRERULE.search(source)):
        return None

    description = ""
    marker = source.find("description")
    if marker >= 0:
        match = _LONG_BRACKET.search(source, marker)
        if match:
            description = match.group(2)

    author_match = _AUTHOR.search(source)
    author = author_match.group(1) if author_match else ""

    categories: List[str] = []
    cat_match = _CATEGORIES.search(source)
    if cat_match:
        for token in cat_match.group(1).split(","):
            token = token.strip().strip('"').strip("'")
            if token:
                categories.append(token)

    explicit: List[int] = []
    for block in _PORT_LIST.findall(source):
        for part in block.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                lo, _, hi = part.partition("-")
                if lo.strip().isdigit() and hi.strip().isdigit():
                    a, b = int(lo), int(hi)
                    if 0 < a <= b <= 65535:
                        explicit.extend(range(a, min(b, a + 64) + 1))
            elif part.isdigit():
                value = int(part)
                if 0 < value <= 65535:
                    explicit.append(value)
    for value in _PORT_EQ.findall(source):
        number = int(value)
        if 0 < number <= 65535:
            explicit.append(number)

    return ScriptInfo(
        name=path.stem,
        path=path,
        description=description,
        author=author,
        categories=tuple(categories),
        has_hostrule=bool(_HAS_HOSTRULE.search(source)),
        has_portrule=bool(_HAS_PORTRULE.search(source)),
        explicit_ports=tuple(sorted(set(explicit))),
    )


@lru_cache(maxsize=1)
def discover_scripts(scripts_dir: str = "") -> Tuple[ScriptInfo, ...]:
    """Return every loadable bundled script, sorted by name."""
    root = Path(scripts_dir) if scripts_dir else SCRIPT_DIR
    if not root.is_dir():
        return ()
    found: List[ScriptInfo] = []
    for path in sorted(root.glob("*.nse")):
        info = _parse_metadata(path)
        if info is not None:
            found.append(info)
    return tuple(found)


def available_categories(scripts: Sequence[ScriptInfo]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for script in scripts:
        for category in script.categories:
            counts[category] = counts.get(category, 0) + 1
    return dict(sorted(counts.items()))


def classify_severity(output: str, script_name: str = "") -> str:
    """Map script output text to a severity label.

    The corpus does not emit machine-readable severities, so this reads the
    conventional NSE phrasings (``VULNERABLE``, ``anonymous login allowed``,
    ``CVE-...``) and falls back to ``info``. Negative results are classified
    first: a script that tested for a CVE and found nothing is not a finding,
    even though its output names the CVE.
    """
    if not output:
        return "info"
    haystack = _TAG_RE.sub(" ", output)
    negative = bool(_NEGATIVE_RE.search(haystack))
    if negative and not _NEGATIVE_OVERRIDE_RE.search(haystack):
        return "info"
    for pattern, severity in _SEVERITY_RULES:
        if re.search(pattern, haystack, re.I):
            return severity
    # A bare CVE id is only a finding when the script says it matched something.
    if re.search(r"\bCVE-\d{4}-\d{4,7}\b", haystack, re.I) and not negative:
        if re.search(r"\b(?:detected|affected|vulnerable|exploitable|confirmed|exposed)\b",
                     haystack, re.I):
            return "high"
    lowered = script_name.lower()
    if any(token in lowered for token in ("injection", "overflow", "rce", "shellshock")):
        return "medium"
    return "info"


# ─────────────────────────────────────────────────────────────────
# ENGINE
# ─────────────────────────────────────────────────────────────────

class NseEngine:
    """Runs the bundled NSE corpus through the local ``nmap`` installation."""

    def __init__(self, scripts_dir: Optional[Path] = None, nmap_path: Optional[str] = None):
        self.scripts_dir = Path(scripts_dir) if scripts_dir else SCRIPT_DIR
        self.nmap = nmap_path or shutil.which("nmap") or ""
        self._lock = threading.Lock()
        self._scripts = discover_scripts(str(self.scripts_dir))

    # ── discovery ────────────────────────────────────────────────
    @property
    def available(self) -> bool:
        return bool(self.nmap) and os.access(self.nmap, os.X_OK)

    @property
    def scripts(self) -> Tuple[ScriptInfo, ...]:
        return self._scripts

    @property
    def categories(self) -> Dict[str, int]:
        return available_categories(self._scripts)

    def get(self, name: str) -> Optional[ScriptInfo]:
        for script in self._scripts:
            if script.name == name:
                return script
        return None

    def select(
        self,
        names: Optional[Iterable[str]] = None,
        categories: Optional[Iterable[str]] = None,
    ) -> List[ScriptInfo]:
        """Resolve a script selection.

        ``names`` accepts exact names, ``all``, a category name, or glob-ish
        prefixes (``http-`` matches every ``http-*`` script). ``categories``
        intersects with the name selection.
        """
        selected: Dict[str, ScriptInfo] = {}

        if names:
            tokens = []
            for entry in names:
                if not entry:
                    continue
                tokens.extend(part.strip() for part in str(entry).split(",") if part.strip())
            for token in tokens:
                lowered = token.lower()
                if lowered in ("all", "*"):
                    for script in self._scripts:
                        selected[script.name] = script
                    continue
                if lowered in self.categories:
                    for script in self._scripts:
                        if lowered in script.categories:
                            selected[script.name] = script
                    continue
                exact = self.get(token)
                if exact is not None:
                    selected[exact.name] = exact
                    continue
                if token.endswith("*"):
                    prefix = token[:-1].lower()
                    for script in self._scripts:
                        if script.name.lower().startswith(prefix):
                            selected[script.name] = script
                    continue
                for script in self._scripts:
                    if script.name.lower().startswith(lowered):
                        selected[script.name] = script
        else:
            for script in self._scripts:
                selected[script.name] = script

        if categories:
            wanted = {c.lower() for c in categories}
            selected = {
                name: script for name, script in selected.items()
                if wanted & {c.lower() for c in script.categories}
            }

        return sorted(selected.values(), key=lambda s: s.name)

    def filter_for_ports(self, scripts: Sequence[ScriptInfo], ports: Sequence[int]) -> List[ScriptInfo]:
        """Drop scripts whose declared port list excludes every open port.

        Scripts without an explicit port list are always kept: their ``portrule``
        decides at runtime and guessing here would silently skip real work.
        """
        open_ports = set(int(p) for p in ports if p)
        if not open_ports:
            return list(scripts)
        kept: List[ScriptInfo] = []
        for script in scripts:
            if not script.explicit_ports or open_ports & set(script.explicit_ports):
                kept.append(script)
        return kept

    # ── execution ────────────────────────────────────────────────
    def run(
        self,
        target: str,
        ports: Sequence[int],
        scripts: Optional[Sequence[ScriptInfo]] = None,
        script_args: Optional[str] = None,
        script_timeout: int = 30,
        host_timeout: int = 300,
        max_parallel: int = 4,
        batch_size: int = 20,
        on_result: Optional[Callable[[ScriptResult], None]] = None,
        on_status: Optional[Callable[[str], None]] = None,
        extra_args: Optional[Sequence[str]] = None,
    ) -> List[ScriptResult]:
        """Run the selected scripts against ``target`` on ``ports``.

        ``ports`` must be the ports the scanner actually found open; nmap still
        applies each script's ``portrule`` on top of that restriction.

        ``host_timeout`` is advisory: it bounds the wall clock of a single
        ``nmap`` process. Per-script limits come from ``script_timeout``, which
        is what keeps a hostile service from stalling the whole run.
        """
        if not self.available:
            return [ScriptResult(
                script="nse", port=0, protocol="", output=[],
                severity="low", error="nmap not installed",
            )]

        chosen = list(scripts if scripts is not None else self._scripts)
        if not chosen:
            return []

        port_list = sorted({int(p) for p in ports if 0 < int(p) <= 65535})
        batches = self._batch(chosen, batch_size)
        results: List[ScriptResult] = []
        started = time.time()

        def worker(batch: Sequence[ScriptInfo]) -> List[ScriptResult]:
            return self._run_batch(
                target, port_list, batch, script_args, script_timeout,
                host_timeout, extra_args,
            )

        if len(batches) == 1:
            batch_results = worker(batches[0])
            for item in batch_results:
                results.append(item)
                if on_result:
                    on_result(item)
        else:
            with ThreadPoolExecutor(max_workers=min(max_parallel, len(batches))) as pool:
                futures = {pool.submit(worker, batch): batch for batch in batches}
                for future in as_completed(futures):
                    try:
                        batch_results = future.result()
                    except Exception as exc:  # pragma: no cover - defensive
                        batch = futures[future]
                        batch_results = [ScriptResult(
                            script=batch[0].name if batch else "nse",
                            port=0, protocol="", output=[],
                            error=str(exc)[:200], severity="low",
                        )]
                    for item in batch_results:
                        results.append(item)
                        if on_result:
                            on_result(item)

        if on_status:
            on_status(
                "nse: %d scripts, %d findings, %.1fs"
                % (len(chosen), len(results), time.time() - started)
            )

        results.sort(key=lambda r: (-SEVERITY_ORDER.get(r.severity, 0), r.port, r.script))
        return results

    def run_for_ports(
        self,
        target: str,
        port_map: Dict[int, str],
        scripts: Optional[Sequence[ScriptInfo]] = None,
        **kwargs,
    ) -> List[ScriptResult]:
        """Convenience wrapper: ``port_map`` is ``{port: service}`` from a scan."""
        ports = sorted(port_map)
        chosen = list(scripts if scripts is not None else self._scripts)
        chosen = self.filter_for_ports(chosen, ports)
        results = self.run(target, ports, chosen, **kwargs)
        for result in results:
            if result.port in port_map:
                service = port_map[result.port]
                if service:
                    result.output = list(result.output)
        return results

    # ── internals ────────────────────────────────────────────────
    NMAP_PARALLELISM = 8

    @staticmethod
    def _batch(scripts: Sequence[ScriptInfo], batch_size: int) -> List[List[ScriptInfo]]:
        """Chunk scripts into fixed-size batches.

        Fixed-size chunks keep a stalled script from costing more than its own
        ``--script-timeout``: nmap runs ``NMAP_PARALLELISM`` scripts at a time,
        so a batch of 20 can never take longer than ~3 rounds.
        """
        ordered = sorted(scripts, key=lambda s: s.name)
        size = max(1, int(batch_size))
        return [ordered[i:i + size] for i in range(0, len(ordered), size)]

    def _build_command(
        self,
        target: str,
        ports: Sequence[int],
        batch: Sequence[ScriptInfo],
        script_args: Optional[str],
        script_timeout: int,
        host_timeout: int,
        extra_args: Optional[Sequence[str]],
    ) -> List[str]:
        command = [
            self.nmap,
            "-Pn", "-n",
            "--script-timeout", "%ds" % max(1, int(script_timeout)),
            "--max-parallelism", str(self.NMAP_PARALLELISM),
            "-oX", "-",
        ]
        if ports:
            command += ["-p", ",".join(str(p) for p in ports)]
        script_paths = ",".join(str(script.path) for script in batch)
        command += ["--script", script_paths]
        if script_args:
            command += ["--script-args", script_args]
        if extra_args:
            command += list(extra_args)
        command.append(target)
        return command

    def _run_batch(
        self,
        target: str,
        ports: Sequence[int],
        batch: Sequence[ScriptInfo],
        script_args: Optional[str],
        script_timeout: int,
        host_timeout: int,
        extra_args: Optional[Sequence[str]],
    ) -> List[ScriptResult]:
        command = self._build_command(
            target, ports, batch, script_args, script_timeout, host_timeout, extra_args,
        )
        started = time.time()
        rounds = max(1, -(-len(batch) // self.NMAP_PARALLELISM))
        budget = max(60, script_timeout * rounds + 45)
        budget = min(budget, max(60, int(host_timeout)))
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=budget,
            )
        except subprocess.TimeoutExpired:
            return [
                ScriptResult(
                    script=script.name, port=0, protocol="",
                    output=[], severity="low", error="timed out after %ds" % budget,
                    categories=script.categories,
                )
                for script in batch
            ]
        except OSError as exc:
            return [
                ScriptResult(
                    script=script.name, port=0, protocol="",
                    output=[], severity="low", error=str(exc)[:200],
                    categories=script.categories,
                )
                for script in batch
            ]

        elapsed = time.time() - started
        results = self._parse_xml(completed.stdout, batch, elapsed)
        if not results and completed.stderr.strip():
            message = completed.stderr.strip().splitlines()[-1][:200]
            return [
                ScriptResult(
                    script=script.name, port=0, protocol="",
                    output=[], severity="low", error=message,
                    categories=script.categories,
                )
                for script in batch
            ]
        return results

    def _parse_xml(
        self,
        xml_text: str,
        batch: Sequence[ScriptInfo],
        elapsed: float,
    ) -> List[ScriptResult]:
        if not xml_text.strip():
            return []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return []

        by_name = {script.name: script for script in batch}
        results: List[ScriptResult] = []

        for host in root.findall("host"):
            for port_node in host.findall("./ports/port"):
                port_id = int(port_node.get("portid", "0") or 0)
                protocol = port_node.get("protocol", "tcp")
                state_node = port_node.find("state")
                state = state_node.get("state", "") if state_node is not None else ""
                if state and state != "open":
                    continue
                for script_node in port_node.findall("script"):
                    name = script_node.get("id", "")
                    info = by_name.get(name)
                    output = self._script_lines(script_node)
                    results.append(ScriptResult(
                        script=name,
                        port=port_id,
                        protocol=protocol,
                        output=output,
                        severity=classify_severity("\n".join(output), name),
                        elapsed=elapsed,
                        categories=info.categories if info else (),
                    ))

            for script_node in host.findall("./hostscript/script"):
                name = script_node.get("id", "")
                info = by_name.get(name)
                output = self._script_lines(script_node)
                results.append(ScriptResult(
                    script=name,
                    port=0,
                    protocol="",
                    output=output,
                    severity=classify_severity("\n".join(output), name),
                    elapsed=elapsed,
                    categories=info.categories if info else (),
                ))

        return results

    @staticmethod
    def _script_lines(script_node: ET.Element) -> List[str]:
        """Flatten a ``<script>`` element into displayable lines."""
        lines: List[str] = []

        def walk(node: ET.Element, depth: int) -> None:
            indent = "  " * depth
            for child in node:
                if child.tag == "elem":
                    key = child.get("key")
                    value = (child.text or "").strip()
                    if key:
                        lines.append("%s%s: %s" % (indent, key, value))
                    elif value:
                        lines.append(indent + value)
                elif child.tag == "table":
                    key = child.get("key")
                    if key:
                        lines.append("%s%s:" % (indent, key))
                    walk(child, depth + 1)
                elif child.tag == "script":
                    walk(child, depth + 1)

        walk(script_node, 0)

        if not lines:
            raw = (script_node.get("output") or "").strip()
            for line in raw.splitlines():
                stripped = line.strip()
                if stripped:
                    lines.append(stripped)

        return lines


# ─────────────────────────────────────────────────────────────────
# MODULE-LEVEL HELPERS
# ─────────────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def get_engine() -> NseEngine:
    return NseEngine()


def list_scripts() -> List[Dict[str, object]]:
    return [script.to_dict() for script in discover_scripts()]


def format_finding(result: ScriptResult) -> str:
    """One-line rendering shared by both front-ends."""
    if result.error:
        return "%-28s %-6s %s" % (result.script, result.port or "-", "ERROR " + result.error)
    return "%-28s %-6s %s" % (
        result.script,
        result.port or "-",
        result.summary or "(no output)",
    )
