def run(host, port, info):
    """Simple script: if HTTP service, return server header details."""
    findings = []
    svc = info.get('service','').lower() if info else ''
    banner = info.get('banner','') if info else ''
    if 'http' in svc or banner and ('http' in banner.lower() or 'server:' in banner.lower()):
        findings.append({
            'script': 'http_server_info',
            'note': 'HTTP server info',
            'banner': banner
        })
    return findings
