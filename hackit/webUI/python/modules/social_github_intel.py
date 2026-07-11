import httpx
import re
import json
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash, IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    username = target.strip().lower()
    if target.startswith("http"):
        parts = target.rstrip("/").split("/")
        username = parts[-1] if parts[-1] else parts[-2]
    username = username.replace("@", "")

    api_url = f"https://api.github.com/users/{username}"
    repo_url = f"https://api.github.com/users/{username}/repos?per_page=100"
    gist_url = f"https://api.github.com/users/{username}/gists?per_page=100"
    org_url = f"https://api.github.com/users/{username}/orgs"
    events_url = f"https://api.github.com/users/{username}/events?per_page=30"

    profile = None
    repos = []
    gists = []
    orgs = []
    events = []

    try:
        resp = await safe_fetch(client, api_url, timeout=15.0,
            headers={"User-Agent": UA, "Accept": "application/vnd.github.v3+json"})
        if resp and resp.status_code == 200:
            profile = resp.json()
    except Exception:
        pass

    if not profile or profile.get("message") == "Not Found":
        findings.append(make_finding(
            entity=f"GitHub user not found: {username}",
            ftype="GitHub: User Not Found",
            source="SocialGitHubIntel",
            confidence="High", color="orange",
            category="Social Media Intelligence",
            threat_level="Informational", status="Not Found",
            tags=["github", "not-found"]
        ))
        return findings

    findings.append(make_finding(
        entity=f"GitHub profile: {profile.get('login', username)}",
        ftype="GitHub: Profile Found",
        source="SocialGitHubIntel",
        confidence="High",
        color="purple",
        category="Social Media Intelligence",
        threat_level="Informational",
        status="Found",
        resolution=profile.get("html_url", f"https://github.com/{username}"),
        tags=["github", "profile", username]
    ))

    fields = [
        ("name", "GitHub: Name"),
        ("company", "GitHub: Company"),
        ("blog", "GitHub: Website/Blog"),
        ("location", "GitHub: Location"),
        ("email", "GitHub: Email"),
        ("bio", "GitHub: Bio"),
        ("twitter_username", "GitHub: Twitter Username"),
    ]

    for field, ftype in fields:
        val = profile.get(field)
        if val:
            findings.append(make_finding(
                entity=f"{field.replace('_', ' ').title()}: {str(val)[:200]}",
                ftype=ftype,
                source="SocialGitHubIntel",
                confidence="High" if field != "bio" else "Medium",
                color="orange" if field in ("email",) else "slate",
                category="Personal Information" if field in ("email", "name") else "Social Media Intelligence",
                threat_level="Elevated Risk" if field == "email" else "Informational",
                status="Exposed" if field == "email" else "Info",
                tags=["github", field, username]
            ))

    stats_fields = [
        ("public_repos", "GitHub: Public Repos", "number"),
        ("public_gists", "GitHub: Public Gists", "number"),
        ("followers", "GitHub: Followers", "number"),
        ("following", "GitHub: Following", "number"),
        ("created_at", "GitHub: Account Created", "date"),
        ("updated_at", "GitHub: Last Updated", "date"),
        ("hireable", "GitHub: Hireable", "bool"),
    ]

    for field, ftype, kind in stats_fields:
        val = profile.get(field)
        if val is not None:
            display = str(val)
            if kind == "date":
                display = str(val)[:10]
            findings.append(make_finding(
                entity=f"{field.replace('_', ' ').title()}: {display[:100]}",
                ftype=ftype,
                source="SocialGitHubIntel",
                confidence="High",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["github", field, username]
            ))

    try:
        resp = await safe_fetch(client, repo_url, timeout=20.0,
            headers={"User-Agent": UA, "Accept": "application/vnd.github.v3+json"})
        if resp and resp.status_code == 200:
            repos = resp.json()
    except Exception:
        pass

    if repos:
        lang_counts = {}
        for repo in repos[:30]:
            lang = repo.get("language")
            if lang:
                lang_counts[lang] = lang_counts.get(lang, 0) + 1

        if lang_counts:
            sorted_langs = sorted(lang_counts.items(), key=lambda x: -x[1])
            findings.append(make_finding(
                entity=f"Languages: {', '.join(f'{l}({c})' for l, c in sorted_langs[:8])}",
                ftype="GitHub: Language Analysis",
                source="SocialGitHubIntel",
                confidence="High",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["github", "languages", username]
            ))

        total_stars = sum(r.get("stargazers_count", 0) for r in repos)
        total_forks = sum(r.get("forks_count", 0) for r in repos)
        topics = set()
        for r in repos:
            for t in r.get("topics", []):
                topics.add(t)

        findings.append(make_finding(
            entity=f"Total stars: {total_stars} | Forks: {total_forks} | Repos: {len(repos)}",
            ftype="GitHub: Repository Stats",
            source="SocialGitHubIntel",
            confidence="High",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["github", "stats", username]
        ))

        if topics:
            findings.append(make_finding(
                entity=f"Topics: {', '.join(list(topics)[:10])}",
                ftype="GitHub: Repository Topics",
                source="SocialGitHubIntel",
                confidence="Medium",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["github", "topics", username]
            ))

        top_repos = sorted(repos, key=lambda r: r.get("stargazers_count", 0), reverse=True)[:5]
        for repo in top_repos:
            findings.append(make_finding(
                entity=f"Repo: {repo['name']} ({repo.get('stargazers_count', 0)} stars, {repo.get('forks_count', 0)} forks)",
                ftype="GitHub: Top Repository",
                source="SocialGitHubIntel",
                confidence="High",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                resolution=repo.get("html_url", ""),
                tags=["github", "repository", repo["name"]]
            ))

        forked_repos = [r for r in repos if r.get("fork")]
        if forked_repos:
            findings.append(make_finding(
                entity=f"Forked repos: {len(forked_repos)}/{len(repos)}",
                ftype="GitHub: Fork Analysis",
                source="SocialGitHubIntel",
                confidence="High",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["github", "forks", username]
            ))

    try:
        resp = await safe_fetch(client, gist_url, timeout=15.0,
            headers={"User-Agent": UA, "Accept": "application/vnd.github.v3+json"})
        if resp and resp.status_code == 200:
            gists = resp.json()
    except Exception:
        pass

    if gists:
        findings.append(make_finding(
            entity=f"Public gists: {len(gists)}",
            ftype="GitHub: Public Gists",
            source="SocialGitHubIntel",
            confidence="High",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["github", "gists", username]
        ))

    try:
        resp = await safe_fetch(client, org_url, timeout=15.0,
            headers={"User-Agent": UA, "Accept": "application/vnd.github.v3+json"})
        if resp and resp.status_code == 200:
            orgs = resp.json()
    except Exception:
        pass

    if orgs:
        org_names = [o.get("login", "") for o in orgs]
        findings.append(make_finding(
            entity=f"Organizations ({len(orgs)}): {', '.join(org_names)}",
            ftype="GitHub: Organization Membership",
            source="SocialGitHubIntel",
            confidence="High",
            color="slate",
            category="Professional Intelligence",
            threat_level="Informational",
            tags=["github", "organizations", username]
        ))

    try:
        resp = await safe_fetch(client, events_url, timeout=15.0,
            headers={"User-Agent": UA, "Accept": "application/vnd.github.v3+json"})
        if resp and resp.status_code == 200:
            events = resp.json()
    except Exception:
        pass

    if events:
        event_types = {}
        for e in events[:50]:
            et = e.get("type", "Unknown")
            event_types[et] = event_types.get(et, 0) + 1
        findings.append(make_finding(
            entity=f"Recent activity: {', '.join(f'{t}({c})' for t, c in sorted(event_types.items(), key=lambda x: -x[1])[:5])}",
            ftype="GitHub: Recent Activity",
            source="SocialGitHubIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["github", "activity", username]
        ))

    commit_emails = set()
    if events:
        for e in events[:30]:
            payload = e.get("payload", {})
            commits = payload.get("commits", [])
            for c in commits:
                author = c.get("author", {})
                email = author.get("email", "")
                if email:
                    commit_emails.add(email)

    if commit_emails:
        findings.append(make_finding(
            entity=f"Emails in commits: {', '.join(list(commit_emails)[:5])}",
            ftype="GitHub: Commit Emails",
            source="SocialGitHubIntel",
            confidence="Medium",
            color="orange",
            category="Personal Information",
            threat_level="Elevated Risk",
            status="Exposed",
            tags=["github", "emails", "pii", username]
        ))

    if profile.get("plan"):
        plan_name = profile["plan"].get("name", "Free")
        findings.append(make_finding(
            entity=f"GitHub plan: {plan_name}",
            ftype="GitHub: Account Plan",
            source="SocialGitHubIntel",
            confidence="High",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["github", "plan", username]
        ))

    ssh_keys = profile.get("public_keys", [])
    if not ssh_keys:
        try:
            keys_resp = await safe_fetch(client, f"https://api.github.com/users/{username}/keys", timeout=10.0,
                headers={"User-Agent": UA, "Accept": "application/vnd.github.v3+json"})
            if keys_resp and keys_resp.status_code == 200:
                ssh_keys = keys_resp.json()
        except Exception:
            pass

    if ssh_keys:
        findings.append(make_finding(
            entity=f"SSH keys: {len(ssh_keys)} key(s) registered",
            ftype="GitHub: SSH Keys",
            source="SocialGitHubIntel",
            confidence="High",
            color="orange",
            category="Security Intelligence",
            threat_level="Standard Target",
            status=f"{len(ssh_keys)} keys",
            tags=["github", "ssh-keys", username]
        ))

    pinned_repos = []
    try:
        pinned_resp = await safe_fetch(client, 
            f"https://api.github.com/users/{username}/pinned?per_page=5",
            timeout=10.0, headers={"User-Agent": UA})
        if pinned_resp and pinned_resp.status_code == 200:
            pinned_repos = pinned_resp.json()
    except Exception:
        pass

    if pinned_repos:
        findings.append(make_finding(
            entity=f"Pinned repos: {len(pinned_repos)}",
            ftype="GitHub: Pinned Repositories",
            source="SocialGitHubIntel",
            confidence="High",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["github", "pinned", username]
        ))

    contribution_data = None
    try:
        contrib_resp = await safe_fetch(client, 
            f"https://github.com/users/{username}/contributions",
            timeout=15.0, headers={"User-Agent": UA})
        if contrib_resp and contrib_resp.status_code == 200:
            contrib_text = contrib_resp.text
            total_contrib = re.search(r'(\d[\d,]*)\s*(?:contribution|Contribution)', contrib_text)
            if total_contrib:
                contribution_data = total_contrib.group(1)
    except Exception:
        pass

    if contribution_data:
        findings.append(make_finding(
            entity=f"Total contributions: {contribution_data}",
            ftype="GitHub: Contribution Graph",
            source="SocialGitHubIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["github", "contributions", username]
        ))

    findings.append(make_finding(
        entity=f"GitHub intelligence gathering complete for {username}",
        ftype="GitHub: Intel Summary",
        source="SocialGitHubIntel",
        confidence="Medium",
        color="purple",
        category="General OSINT",
        threat_level="Informational",
        status="Complete",
        raw_data=f"Repos: {len(repos)} | Gists: {len(gists)} | Orgs: {len(orgs)} | Followers: {profile.get('followers', 0)}",
        tags=["github", "summary"]
    ))

    return findings
