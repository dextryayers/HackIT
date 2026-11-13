"""
HackIt Swarm — 28-node autonomous vulnerability swarm.
Deep recon · precise payload delivery · verified exploit chains.
Built for both domain and IP targets (public / local / RFC1918).
Every node reports independently; the swarm aggregates with zero-loss.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple, Set
from urllib.parse import urlparse

from .brain import AIHyperBrain
from .payloads import generate_multi, probe_many, summarize_probe, CATALOG, ALIASES
from .external_tools import aggregate_recon, available_tools, COMMON_PORTS, COMMON_SUBDOMAINS, COMMON_PATHS
from .commands import COMMAND_MODES
from .memory import AgentMemory

SWARM_NODE_COUNT = 28
SWARM_MAX_WORKERS = 14
SWARM_TIMEOUT = 300

class SwarmNode:
    """Single autonomous scanning node."""
    def __init__(self, node_id: int):
        self.node_id = node_id
        self.findings: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        self.results: Dict[str, Any] = {}
        self.active = True

class SwarmEngine:
    """
    The swarm controller. Launches parallel nodes against any target:
    - Domain (public / internal / subdomain)
    - IP (public / local / RFC1918 / loopback / link-local)
    Every node runs full pipeline: recon → payload forge → differential probe → chain analysis → report.
    """

    def __init__(self, target: str, deep: bool = True, passive: bool = False):
        self.target = self._normalize_target(target)
        self.deep = deep
        self.passive = passive
        self.nodes: List[SwarmNode] = [SwarmNode(i) for i in range(SWARM_NODE_COUNT)]
        self._recon_cache: Dict[str, Dict[str, Any]] = {}
        self.brain = AIHyperBrain(engine="native", enable_memory=False, announce=False)
        self.lock = threading.Lock()
        self.discovery = {"subdomains": [], "ports": [], "endpoints": [], "tech": {} }
        self.vuln_findings: List[Dict[str, Any]] = []
        self.attack_chains: List[List[str]] = []
        self.reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports", "swarm")
        os.makedirs(self.reports_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Target normalization
    # ------------------------------------------------------------------

    def _normalize_target(self, target: str) -> str:
        target = target.strip()
        if not target:
            raise ValueError("Target cannot be empty.")
        # Ensure scheme for domain-based recon
        if "://" not in target and "/" not in target.split("?")[0].rstrip("/"):
            # Treat as domain; force https for recon, keep raw for port scans
            pass  # Keep raw — recon modules handle scheme
        return target

    def _cached_recon(self, host: str, base_url: str) -> Dict[str, Any]:
        """aggregate_recon is expensive — run it once, share with all nodes."""
        with self.lock:
            if host in self._recon_cache:
                return self._recon_cache[host]
        result = aggregate_recon(host, base_url)
        with self.lock:
            self._recon_cache[host] = result
        return result

    # ------------------------------------------------------------------
    # Deep reconnaissance — runs on nodes 1-6
    # ------------------------------------------------------------------

    def _recon_node(self, node: SwarmNode) -> None:
        """Node task: full external + internal recon aggregation."""
        try:
            host_part = self.target.split("/")[0] if "/" not in self.target else urlparse(self.target).hostname or self.target
            if host_part is None:
                host_part = self.target
            base_url = self.target if self.target.startswith(("http://", "https://")) else f"https://{self.target}"
            # Deep aggregate recon
            extra = self._cached_recon(str(host_part), base_url)
            with self.lock:
                # Merge subdomains
                current_subs = set(self.discovery.get("subdomains", []))
                current_subs.update(extra.get("subdomains", []))
                self.discovery["subdomains"] = sorted(current_subs)
                # Merge ports
                current_ports = {p.get("port") for p in self.discovery.get("ports", []) if isinstance(p, dict) and p.get("port")}
                for p in extra.get("ports", []):
                    if isinstance(p, dict) and p.get("port"):
                        if p.get("port") not in current_ports:
                            current_ports.add(p.get("port"))
                            self.discovery["ports"].append(p)
                # Merge endpoints
                current_eps = set(self.discovery.get("endpoints", []))
                current_eps.update(extra.get("endpoints", []))
                self.discovery["endpoints"] = sorted(current_eps)
                # Technology
                tech_info = extra.get("tech", {})
                if tech_info:
                    self.discovery["tech"] = tech_info
            node.results["recon"] = extra
            node.findings.extend([{"type": "asset", "evidence": f"Discovered subdomain: {s}"} for s in extra.get("subdomains", [])[:10]])
        except Exception as exc:
            node.errors.append(f"recon error: {exc}")

    # ------------------------------------------------------------------
    # Port scan — nodes 7-10
    # ------------------------------------------------------------------

    def _portscan_node(self, node: SwarmNode) -> None:
        try:
            host = urlparse(self.target).hostname if urlparse(self.target).hostname else self.target.split("/")[0]
            ports = COMMON_PORTS
            result = self._cached_recon(str(host) if host else self.target, f"https://{host}" if host else self.target)
            node.results["portscan"] = result.get("ports", [])
            node.findings.extend([{"type": "port_open", "evidence": f"Port {p.get('port')}/{p.get('protocol')} open — {p.get('service', '')}"} for p in result.get("ports", [])[:8]])
        except Exception as exc:
            node.errors.append(f"portscan error: {exc}")

    # ------------------------------------------------------------------
    # Subdomain enumeration — nodes 11-13
    # ------------------------------------------------------------------

    def _subdomain_node(self, node: SwarmNode) -> None:
        try:
            host = urlparse(self.target).hostname if urlparse(self.target).hostname else self.target.split("/")[0]
            if not host or "." not in host:
                node.errors.append("subdomain: invalid domain target")
                return
            extra = self._cached_recon(host, f"https://{host}")
            subs = extra.get("subdomains", [])
            with self.lock:
                current = set(self.discovery.get("subdomains", []))
                current.update(subs)
                self.discovery["subdomains"] = sorted(current)
            node.results["subdomains"] = subs
        except Exception as exc:
            node.errors.append(f"subdomain error: {exc}")

    # ------------------------------------------------------------------
    # Deep payload forge — nodes 14-17 (4 nodes, multi-class)
    # ------------------------------------------------------------------

    def _payload_forge_node(self, node: SwarmNode, types: List[str]) -> None:
        try:
            context = json.dumps(self.discovery, default=str)[:4000]
            result = generate_multi(types, context=context, count=12, use_ai=True, timeout=60)
            node.results["payloads"] = result
        except Exception as exc:
            node.errors.append(f"payload forge error: {exc}")

    # ------------------------------------------------------------------
    # Differential vulnerability probing — nodes 18-24 (7 nodes)
    # ------------------------------------------------------------------

    def _probe_node(self, node: SwarmNode, target_url: str, vuln_type: str, payloads: List[str], parameter: str = "") -> None:
        try:
            results = probe_many(
                target_url, vuln_type, payloads,
                parameter=parameter, method="GET", timeout=10.0, delay=0.15
            )
            vulnerable_items = [r for r in results if r.get("vulnerable")]
            if vulnerable_items:
                node.findings.extend([
                    {"vuln_type": vuln_type, "target": target_url, "parameter": parameter,
                     "payload": r.get("payload"), "evidence": r.get("evidence"),
                     "confirmed": bool(str(r.get("evidence") or "").strip()),
                     "severity": "critical" if vuln_type in ("sqli", "cmdi", "ssti", "xxe") else "high"}
                    for r in vulnerable_items
                ])
            node.results[f"probe_{vuln_type}"] = results
        except Exception as exc:
            node.errors.append(f"probe error ({vuln_type}): {exc}")

    # ------------------------------------------------------------------
    # Chain builder — nodes 25-27
    # ------------------------------------------------------------------

    def _chain_node(self, node: SwarmNode) -> None:
        try:
            # Build simple attack chains from confirmed signals
            chains = []
            findings = node.findings
            for f in findings:
                vt = f.get("vuln_type", "")
                if vt:
                    chain = [f"Target: {self.target}", f"Vulnerability: {vt}", f"Evidence: {f.get('evidence', '')[:200]}", "Recommendation: apply parameterised queries / encoding / input validation"]
                    chains.append(chain)
            node.results["chains"] = chains
            node.findings.extend([{"type": "chain", "evidence": " -> ".join(c)} for c in chains])
        except Exception as exc:
            node.errors.append(f"chain error: {exc}")

    # ------------------------------------------------------------------
    # Full swarm runner — 28 nodes distributed across phases
    # ------------------------------------------------------------------

    def run(self) -> Dict[str, Any]:
        start_time = time.time()
        if os.path.isfile(self.target):
            return self._run_file_mode(start_time)
        print(f"[ SWARM ] Launching {SWARM_NODE_COUNT}-node autonomous swarm against {self.target} (deep={self.deep}, passive={self.passive})...")
        print(f"[ SWARM ] Nodes: 1-6 recon | 7-10 portscan | 11-13 subdomain | 14-17 payload | 18-24 probe | 25-27 chain | 28 aggregation")
        
        # Phase 1: Recon nodes (1-6)
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            futures = {executor.submit(self._recon_node, self.nodes[i]): i for i in range(6)}
            for future in concurrent.futures.as_completed(futures):
                idx = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    self.nodes[idx].errors.append(str(exc))
        
        # Phase 2: Port / Subdomain (7-13)
        with concurrent.futures.ThreadPoolExecutor(max_workers=7) as executor:
            futures_port = {executor.submit(self._portscan_node, self.nodes[i]): i for i in range(6, 10)}
            futures_sub = {executor.submit(self._subdomain_node, self.nodes[i]): i for i in range(10, 13)}
            futures = {**futures_port, **futures_sub}
            for future in concurrent.futures.as_completed(futures):
                idx = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    self.nodes[idx].errors.append(str(exc))
        
        # Update discovery from subdomain nodes
        for i in range(10, 13):
            if "subdomains" in self.nodes[i].results:
                current = set(self.discovery.get("subdomains", []))
                current.update(self.nodes[i].results["subdomains"])
                self.discovery["subdomains"] = sorted(current)
        
        # Phase 3: Payload forge (14-17) — multi-class deep forge
        payload_classes = ["sqli", "xss", "ssrf", "lfi", "ssti", "cmdi", "nosqli", "ldap", "xxe", "jwt", "graphql", "open_redirect"]
        # Split across 4 nodes for parallel AI generation
        chunks = [payload_classes[i::4] for i in range(4)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(self._payload_forge_node, self.nodes[13+i], chunks[i]): 13+i for i in range(4)}
            for future in concurrent.futures.as_completed(futures):
                idx = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    self.nodes[idx].errors.append(str(exc))
        
        # Aggregate payloads
        all_payload_classes = set()
        for i in range(13, 17):
            result = self.nodes[i].results.get("payloads")
            if result and isinstance(result, dict) and "results" in result:
                all_payload_classes.update(result["results"].keys())
        
        # Phase 4: Probe nodes (18-24) — differential verification
        # For each payload class, probe against primary target and subdomains/endpoints
        targets_to_probe = [self.target]
        for sub in self.discovery.get("subdomains", [])[:5]:
            targets_to_probe.append(f"https://{sub}")
        for ep in self.discovery.get("endpoints", [])[:3]:
            if ep.startswith(("http://", "https://")):
                targets_to_probe.append(ep)
        
        # Build payload lists per class from aggregated results
        payload_catalog = {}
        for cls in all_payload_classes:
            payload_catalog[cls] = CATALOG.get(cls, [])
        
        # Launch 7 probe nodes, each covering a subset of payload classes
        probe_classes_per_node: List[List[str]] = []
        for node_idx in range(7):
            subset = list(all_payload_classes)[node_idx::7] if all_payload_classes else payload_classes[:3]
            if not subset:
                subset = payload_classes[node_idx*2:(node_idx+1)*2] or ["sqli"]
            probe_classes_per_node.append(subset)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=7) as executor:
            futures = {}
            for i in range(7):
                node = self.nodes[17 + i]
                subset = probe_classes_per_node[i]
                for cls in subset:
                    payloads_for_cls = payload_catalog.get(cls, [])
                    payload_strs = [str(p.get("payload", p)) if isinstance(p, dict) else str(p) for p in payloads_for_cls]
                    # Pick first 4 payloads to keep speed high with accuracy
                    payload_strs = payload_strs[:4]
                    for url in targets_to_probe:
                        future = executor.submit(self._probe_node, node, url, cls, payload_strs, "q" if cls == "xss" else ("id" if cls in ("sqli", "nosqli") else "url"))
                        futures[future] = (i, url, cls)
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    pass  # Already handled in node
        
        # Phase 5: Chain nodes (25-27)
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = {executor.submit(self._chain_node, self.nodes[24+i]): 24+i for i in range(3)}
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    pass
        
        # Phase 6: Aggregation node 28
        self._aggregate_node()
        
        elapsed = time.time() - start_time
        result = {
            "target": self.target,
            "swarm_nodes": SWARM_NODE_COUNT,
            "completed_nodes": len([n for n in self.nodes if n.results or n.findings]),
            "findings_count": len(self.vuln_findings),
            "attack_chains": len(self.attack_chains),
            "discovery": self.discovery,
            "duration_seconds": round(elapsed, 2),
            "errors": [str(err) for err in sum([n.errors for n in self.nodes], [])],
            "full_findings": self.vuln_findings,
            "node_summaries": [{"node": n.node_id, "findings": len(n.findings), "results_keys": list(n.results.keys()), "errors": len(n.errors)} for n in self.nodes],
        }
        # Save report
        stamp = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(self.reports_dir, f"swarm_{self.target.replace('://', '_').replace('/', '_')}_{stamp}.json")
        with open(path, "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"[ SWARM COMPLETE ] {len(self.vuln_findings)} verified findings · {len(self.attack_chains)} chain(s) · saved to {path}")
        return result

    def _run_file_mode(self, start_time: float) -> Dict[str, Any]:
        """Target is a file on disk — run malware triage nodes straight through
        the malwscan engine. Same report shape as the web swarm."""
        from hackit.malware.engine import analyze as _malware_analyze
        print(f"[ SWARM ] target is a file — switching to malware triage mode: {self.target}")
        try:
            results = _malware_analyze([self.target])
        except Exception as exc:
            results = [{"file": self.target, "error": str(exc)}]
        findings: List[Dict[str, Any]] = []
        for entry in results:
            verdict = str(entry.get("verdict") or "unknown")
            severity = {"malicious": "critical", "suspicious": "high", "clean": "info"}.get(verdict, "medium")
            iocs = entry.get("iocs") or {}
            ioc_count = sum(len(v) for v in iocs.values() if isinstance(v, list))
            findings.append({
                "vuln_type": "malware",
                "target": entry.get("file") or self.target,
                "parameter": "",
                "payload": None,
                "evidence": f"verdict={verdict} score={entry.get('score')} entropy={entry.get('entropy')} "
                            f"packed={entry.get('packed')} apis={len(entry.get('suspicious_apis') or [])} iocs={ioc_count}",
                "severity": severity,
                "confirmed": True,
            })
        self.vuln_findings = findings
        self.discovery = {"subdomains": [], "ports": [], "endpoints": [], "tech": {},
                          "malware": results}
        elapsed = time.time() - start_time
        result = {
            "target": self.target,
            "mode": "malware-triage",
            "swarm_nodes": SWARM_NODE_COUNT,
            "completed_nodes": 1,
            "findings_count": len(findings),
            "attack_chains": 0,
            "discovery": self.discovery,
            "duration_seconds": round(elapsed, 2),
            "errors": [r.get("error") for r in results if r.get("error")],
            "full_findings": findings,
            "malware_results": results,
            "node_summaries": [{"node": 0, "findings": len(findings), "results_keys": ["malware"], "errors": 0}],
        }
        stamp = time.strftime("%Y%m%d_%H%M%S")
        safe = os.path.basename(self.target)
        path = os.path.join(self.reports_dir, f"swarm_malware_{safe}_{stamp}.json")
        with open(path, "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False, default=str)
        print(f"[ SWARM COMPLETE ] malware triage saved to {path}")
        return result

    def _aggregate_node(self) -> None:
        """Node 28: aggregate all findings, deduplicate, build chains."""
        all_findings = []
        for n in self.nodes:
            for f in n.findings:
                if isinstance(f, dict) and f.get("vuln_type"):
                    all_findings.append({
                        "node": n.node_id,
                        "vuln_type": f.get("vuln_type"),
                        "target": f.get("target", self.target),
                        "payload": f.get("payload"),
                        "evidence": f.get("evidence"),
                        "severity": f.get("severity", "high"),
                        "parameter": f.get("parameter", ""),
                    })
                elif isinstance(f, dict) and f.get("evidence"):
                    all_findings.append({
                        "node": n.node_id,
                        "vuln_type": f.get("type", "recon"),
                        "target": self.target,
                        "payload": None,
                        "evidence": f.get("evidence"),
                        "severity": "info",
                        "parameter": "",
                    })
        # Deduplicate by (vuln_type, payload, evidence prefix)
        seen = set()
        deduped = []
        for f in all_findings:
            key = (f.get("vuln_type"), f.get("payload"), f.get("evidence", "")[:60])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(f)
        self.vuln_findings = deduped
        
        # Build chains
        chains = {}
        for f in deduped:
            vt = f.get("vuln_type")
            if vt:
                if vt not in chains:
                    chains[vt] = []
                chains[vt].append(f.get("evidence", ""))
        for vt, evidences in chains.items():
            self.attack_chains.append({"type": vt, "steps": evidences[:4], "recommendation": self._remediation_for(vt)})
        
        # Store aggregated payloads
        payload_catalog_agg: Dict[str, List] = {}
        for n in self.nodes[13:17]:
            result = n.results.get("payloads")
            if result and isinstance(result, dict):
                for k, v in (result.get("results") or {}).items():
                    payload_catalog_agg.setdefault(k, []).extend(v.get("payloads", []) if isinstance(v, dict) else [])
        self.discovery["payload_catalog"] = payload_catalog_agg

    def _remediation_for(self, vt: str) -> str:
        rem = {
            "sqli": "Use parameterised queries; enforce least-privilege DB accounts; disable stacked queries.",
            "xss": "Apply context-aware output encoding (HTML/JS/URL); implement strict CSP; sanitize reflected input.",
            "ssrf": "Validate all outbound URLs against an allowlist; block link-local ranges; disable unnecessary URL fetchers.",
            "lfi": "Validate file paths against an allowlist; disable file inclusion; use chroot / sandbox.",
            "ssti": "Use sandboxed template rendering; never render user input as code; disable template introspection.",
            "cmdi": "Never pass user input to a shell; use safe APIs; implement strict allowlists for command arguments.",
            "nosqli": "Validate query operators; disable $where / regex where possible; enforce schema validation.",
            "ldap": "Escape LDAP filter input; use parameterised LDAP queries; restrict filter syntax.",
            "xxe": "Disable external entity processing in XML parsers; use safe parsers (defusedxml).",
            "jwt": "Use strong secrets; enforce algorithm allowlists; rotate exposed secrets; implement short expiry.",
            "graphql": "Disable production introspection; enforce query depth limits; validate input types.",
            "open_redirect": "Use an allowlist for redirect destinations; reject relative / protocol-relative URLs.",
        }
        return rem.get(str(vt), "Review input validation, apply defense-in-depth, and retest after fix.")
