import httpx
import asyncio
import re
from module_common import safe_fetch, safe_fetch_json, make_finding, resolve_ip, is_ip
from models import IntelligenceFinding

CONTAINER_ORCHESTRATORS = {
    "Kubernetes": ["k8s", "kubernetes", "kube-api", "kubelet", "kubeproxy", ".k8s."],
    "Docker Swarm": ["swarm", "docker-swarm", ".swarm."],
    "Nomad": ["nomad", "nomadproject", ".nomad."],
    "OpenShift": ["openshift", "okd", "openshiftapps.com"],
    "Rancher": ["rancher", "rancher-server", ".rancher."],
    "Amazon ECS": ["ecs.amazonaws.com", "ecs-", "amazonaws.com"],
    "Amazon EKS": ["eks.amazonaws.com", "eks-", "amazonaws.com"],
    "Google GKE": ["gke.googleapis.com", "gke", "container.googleapis.com"],
    "Azure AKS": ["aks-", "azmk8s.io", "azure.com"],
    "Oracle OKE": ["oke.oraclecloud.com", "containerengine.oraclecloud"],
    "DigitalOcean DOKS": ["doks.digitalocean", "k8s.digitalocean"],
    "Linode LKE": ["lke.linode.com", "k8s.linode.com"],
    "IBM IKS": ["iks.cloud.ibm", "containers.cloud.ibm"],
    "Alibaba ACK": ["ack.aliyuncs.com", "cs.aliyuncs.com"],
    "Tencent TKE": ["tke.tencentcloud.com", "ccs.tencentcloud"],
}

CONTAINER_RUNTIMES = {
    "Docker": ["docker", "containerd", "runc", "docker.io"],
    "containerd": ["containerd", "ctr"],
    "CRI-O": ["cri-o", "crio"],
    "Podman": ["podman", "libpod"],
    "LXC/LXD": ["lxc", "lxd", "linuxcontainers"],
    "rkt": ["rkt", "rocket"],
}

K8S_API_PATHS = [
    "/api/v1",
    "/apis/apps/v1",
    "/api/v1/namespaces",
    "/api/v1/pods",
    "/api/v1/services",
    "/api/v1/nodes",
    "/healthz",
    "/readyz",
    "/livez",
    "/openapi/v2",
    "/version",
    "/api",
    "/apis",
    "/.well-known/openid-configuration",
]

REGISTRY_PATTERNS = {
    "Docker Hub": ["docker.io", "docker.com", "registry-1.docker"],
    "Google GCR": ["gcr.io", "gcr.", "container-registry"],
    "AWS ECR": ["ecr.amazonaws.com", "ecr-", "amazonaws.com"],
    "Azure ACR": ["azurecr.io", "azurecr.", "azcr.io"],
    "GitHub GHCR": ["ghcr.io", "ghcr.", "github.com"],
    "Quay": ["quay.io", "quay.", "quay"],
    "Harbor": ["harbor", "harbor.io"],
    "GitLab Registry": ["registry.gitlab", "gitlab.com"],
    "DigitalOcean DCR": ["registry.digitalocean", "docker.digitalocean"],
    "Oracle OCI Registry": ["ocir.io", "ocir.", "oraclecloud"],
    "IBM Cloud CR": ["icr.io", "icr.", "cloud.ibm"],
    "Alibaba ACR": ["cr.aliyuncs.com", "aliyuncs.com"],
    "Tencent TCR": ["ccr.ccs.tencentyun.com", "tencentyun.com"],
    "Nexus": ["nexus", "sonatype"],
    "JFrog Artifactory": ["jfrog", "artifactory", "jfrog.io"],
    "Cloudsmith": ["cloudsmith.io", "cloudsmith"],
    "Canister": ["canister.io", "canister"],
}

KUBECONFIG_PATHS = [
    "/.kube/config",
    "/kubeconfig",
    "/admin.conf",
    "/kube-config",
    "/kubeconfig.yaml",
    "/kubernetes/kubeconfig",
    "/etc/kubernetes/kubelet.conf",
]

DOCKER_PATHS = [
    "/.docker/config.json",
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/Dockerfile",
    "/.dockerignore",
    "/docker-compose.override.yml",
    "/docker-compose.prod.yml",
]

HELM_PATHS = [
    "/helm/",
    "/charts/",
    "/Chart.yaml",
    "/values.yaml",
]

async def _resolve_target(target: str) -> tuple:
    t = target.strip()
    if is_ip(t):
        return t, True
    ip = resolve_ip(t)
    if ip:
        return ip, False
    return None, "DNS resolution failed"

async def _check_dns_orchestration(target: str) -> list:
    findings = []
    try:
        loop = asyncio.get_event_loop()
        try:
            answers = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'CNAME'))
            for r in answers:
                cname = str(r.target).rstrip('.').lower()
                for orch, patterns in CONTAINER_ORCHESTRATORS.items():
                    for pat in patterns:
                        if pat in cname:
                            findings.append(make_finding(
                                entity=orch,
                                type="Container Orchestrator (CNAME)",
                                source="ContainerScanner",
                                confidence="High",
                                color="purple",
                                category="Cloud / Infrastructure OSINT",
                                threat_level="Informational",
                                status="Detected",
                                resolution=cname,
                                raw_data=f"CNAME {cname} matches {orch} pattern '{pat}'",
                                tags=["cloud", "container", orch.lower().replace(" ", "-")]
                            ))
                            break
        except Exception:
            pass
        try:
            answers_txt = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'TXT'))
            for r in answers_txt:
                txt = str(r).lower()
                for reg, patterns in REGISTRY_PATTERNS.items():
                    for pat in patterns:
                        if pat in txt:
                            findings.append(make_finding(
                                entity=reg,
                                type="Container Registry (TXT)",
                                source="ContainerScanner",
                                confidence="High",
                                color="blue",
                                category="Cloud / Infrastructure OSINT",
                                threat_level="Informational",
                                status="Detected",
                                raw_data=f"TXT record indicates {reg} registry: {txt[:100]}",
                                tags=["cloud", "container", "registry", reg.lower().replace(" ", "-").replace(".", "")]
                            ))
                            break
        except Exception:
            pass
    except Exception:
        pass
    return findings

async def _check_api_endpoints(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    base = f"https://{target}" if not target.startswith("http") else target
    for path in K8S_API_PATHS:
        url = f"{base}{path}"
        try:
            resp = await safe_fetch(client, url, timeout=5.0,
                headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                body = resp.text[:200].lower()
                if "apiVersion" in body or "kind" in body or "kubernetes" in body or "namespaces" in body:
                    findings.append(make_finding(
                        entity=f"K8s API: {url}",
                        type="Kubernetes API Endpoint (Exposed)",
                        source="ContainerScanner",
                        confidence="High",
                        color="red",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Critical",
                        status="Exposed",
                        resolution=url,
                        raw_data=f"Kubernetes API endpoint accessible at {url}",
                        tags=["cloud", "kubernetes", "api", "exposed"]
                    ))
                else:
                    findings.append(make_finding(
                        entity=f"K8s Path Responds: {url}",
                        type="Kubernetes Path Response",
                        source="ContainerScanner",
                        confidence="Medium",
                        color="orange",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Medium",
                        status="Responds",
                        resolution=url,
                        raw_data=f"K8s path {path} returned {resp.status_code}",
                        tags=["cloud", "kubernetes", "api"]
                    ))
        except Exception:
            continue
    return findings

async def _check_config_paths(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    base = f"https://{target}" if not target.startswith("http") else target
    all_paths = KUBECONFIG_PATHS + DOCKER_PATHS + HELM_PATHS
    for path in all_paths:
        url = f"{base}{path}"
        try:
            resp = await safe_fetch(client, url, timeout=5.0,
                headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                findings.append(make_finding(
                    entity=f"Config Exposed: {path}",
                    type="Container Config Exposure",
                    source="ContainerScanner",
                    confidence="High",
                    color="red",
                    category="Cloud / Infrastructure OSINT",
                    threat_level="Critical",
                    status="Exposed",
                    resolution=url,
                    raw_data=f"Sensitive config file exposed at {url} [{resp.status_code}]",
                    tags=["cloud", "container", "config", "exposed"]
                ))
        except Exception:
            continue
    return findings

async def _analyze_headers(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    base = f"https://{target}" if not target.startswith("http") else target
    try:
        resp = await safe_fetch(client, base, follow_redirects=True, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        headers = dict(resp.headers)
        server = headers.get("server", "").lower()
        all_vals = " ".join(str(v).lower() for v in headers.values())

        for runtime, patterns in CONTAINER_RUNTIMES.items():
            for pat in patterns:
                if pat in server or pat in all_vals:
                    findings.append(make_finding(
                        entity=f"Container Runtime: {runtime}",
                        type="Container Runtime Detection",
                        source="ContainerScanner",
                        confidence="High",
                        color="orange",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Detected",
                        raw_data=f"Container runtime {runtime} detected ({pat})",
                        tags=["cloud", "container", runtime.lower().replace(" ", "-").replace("/", "")]
                    ))
                    break

        for orch, patterns in CONTAINER_ORCHESTRATORS.items():
            for pat in patterns:
                if pat in server or pat in all_vals:
                    findings.append(make_finding(
                        entity=orch,
                        type="Container Orchestrator (Header)",
                        source="ContainerScanner",
                        confidence="High",
                        color="orange",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Detected",
                        raw_data=f"Orchestrator {orch} detected in headers ({pat})",
                        tags=["cloud", "container", orch.lower().replace(" ", "-")]
                    ))
                    break

        for reg, patterns in REGISTRY_PATTERNS.items():
            for pat in patterns:
                if pat in all_vals:
                    findings.append(make_finding(
                        entity=reg,
                        type="Container Registry (Header)",
                        source="ContainerScanner",
                        confidence="Medium",
                        color="blue",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Suspected",
                        raw_data=f"Registry {reg} pattern '{pat}' found in headers",
                        tags=["cloud", "container", "registry", reg.lower().replace(" ", "-").replace(".", "")]
                    ))
                    break

        html = resp.text[:50000].lower() if hasattr(resp, "text") else ""
        for reg, patterns in REGISTRY_PATTERNS.items():
            for pat in patterns:
                if pat in html:
                    findings.append(make_finding(
                        entity=reg,
                        type="Container Registry (HTML)",
                        source="ContainerScanner",
                        confidence="Medium",
                        color="blue",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Suspected",
                        raw_data=f"Registry {reg} pattern '{pat}' found in HTML",
                        tags=["cloud", "container", "registry", reg.lower().replace(" ", "-").replace(".", "")]
                    ))
                    break

    except Exception as e:
        findings.append(make_finding(
            entity=f"Header analysis error: {str(e)[:100]}",
            type="Container Scan Error",
            source="ContainerScanner",
            confidence="Low",
            color="red",
            category="Cloud / Infrastructure OSINT",
            threat_level="Informational",
            raw_data=str(e)[:200],
            tags=["error"]
        ))
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    target = target.strip().lower()
    if target.startswith("http"):
        from urllib.parse import urlparse
        target = urlparse(target).netloc

    ip, is_ip = await _resolve_target(target)
    if ip is None:
        findings.append(make_finding(entity=f"DNS resolution failed: {target}", type="DNS Error", source="ContainerScanner", confidence="Low", color="red", category="Cloud / Infrastructure OSINT", raw_data=str(is_ip)[:200], tags=["error"]))
        return findings

    if not is_ip:
        findings.append(make_finding(entity=f"{target} -> {ip}", type="DNS Resolution", source="ContainerScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", threat_level="Informational", status="Resolved", resolution=ip, tags=["dns", "resolution"]))

    findings.extend(await _check_dns_orchestration(target))
    findings.extend(await _analyze_headers(target, client))
    findings.extend(await _check_api_endpoints(target, client))
    findings.extend(await _check_config_paths(target, client))

    orch_count = sum(1 for f in findings if "Orchestrator" in f.type)
    runtime_count = sum(1 for f in findings if "Runtime" in f.type)
    api_count = sum(1 for f in findings if "Kubernetes API" in f.type or "K8s Path" in f.type)
    registry_count = sum(1 for f in findings if "Registry" in f.type)
    config_count = sum(1 for f in findings if "Config Exposure" in f.type)

    findings.append(make_finding(entity=f"Orchestrators detected: {orch_count}", type="Orchestrator Count", source="ContainerScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["container", "summary"]))
    findings.append(make_finding(entity=f"Container runtimes: {runtime_count}", type="Runtime Count", source="ContainerScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["container", "summary"]))
    findings.append(make_finding(entity=f"K8s API endpoints: {api_count}", type="K8s API Count", source="ContainerScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["container", "summary"]))
    findings.append(make_finding(entity=f"Container registries: {registry_count}", type="Registry Count", source="ContainerScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["container", "summary"]))
    findings.append(make_finding(entity=f"Config exposures: {config_count}", type="Config Exposure Count", source="ContainerScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["container", "summary"]))
    findings.append(make_finding(entity=f"Target: {target}", type="Container Scan Target", source="ContainerScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", tags=["container", "target"]))
    findings.append(make_finding(entity=f"Total container findings: {len(findings)}", type="Container Scan Summary", source="ContainerScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["container", "summary"]))

    return findings
