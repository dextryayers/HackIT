import httpx
import re
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

ROLE_PATTERNS = [
    ("admin", "Administrator", "High"),
    ("info", "General Information", "Medium"),
    ("support", "Customer Support", "Medium"),
    ("sales", "Sales Department", "Medium"),
    ("contact", "General Contact", "Medium"),
    ("help", "Help Desk", "Medium"),
    ("webmaster", "Webmaster", "High"),
    ("postmaster", "Postmaster", "High"),
    ("hostmaster", "Hostmaster", "High"),
    ("marketing", "Marketing Department", "Medium"),
    ("billing", "Billing Department", "High"),
    ("careers", "Careers/HR", "Medium"),
    ("jobs", "Job Applications", "Medium"),
    ("hr", "Human Resources", "Medium"),
    ("recruitment", "Recruitment", "Medium"),
    ("partners", "Partner Relations", "Medium"),
    ("press", "Press/Media Relations", "Medium"),
    ("media", "Media Inquiries", "Medium"),
    ("legal", "Legal Department", "High"),
    ("abuse", "Abuse Reporting", "High"),
    ("noc", "Network Operations", "High"),
    ("security", "Security Team", "High"),
    ("privacy", "Privacy Office", "High"),
    ("copyright", "Copyright Agent", "High"),
    ("dmca", "DMCA Agent", "High"),
    ("noreply", "No-Reply (Automated)", "Low"),
    ("no-reply", "No-Reply (Automated)", "Low"),
    ("newsletter", "Newsletter", "Low"),
    ("feedback", "Feedback", "Low"),
    ("enquiries", "Enquiries", "Medium"),
    ("office", "General Office", "Medium"),
    ("team", "Team Email", "Medium"),
    ("hello", "General Contact", "Low"),
    ("hi", "General Contact", "Low"),
    ("register", "Registration", "Medium"),
    ("registrar", "Registrar", "High"),
    ("subscribe", "Subscriptions", "Low"),
    ("unsubscribe", "Unsubscribe", "Low"),
    ("invite", "Invitations", "Low"),
    ("notify", "Notifications", "Low"),
    ("notification", "Notifications", "Low"),
    ("alert", "Alerts", "Low"),
    ("alerts", "Alerts", "Low"),
    ("monitor", "Monitoring", "Medium"),
    ("status", "Status Updates", "Medium"),
    ("update", "Updates", "Low"),
    ("updates", "Updates", "Low"),
    ("confirm", "Confirmations", "Low"),
    ("verify", "Verification", "Medium"),
    ("validation", "Validation", "Medium"),
    ("test", "Testing", "Low"),
    ("dev", "Development", "Low"),
    ("developer", "Developer", "Low"),
    ("engineering", "Engineering", "Medium"),
    ("it", "IT Department", "Medium"),
    ("sysadmin", "System Administrator", "High"),
    ("root", "Root Administrator", "High"),
    ("mailer", "Mailer Daemon", "Low"),
    ("mail", "Mail Server", "Medium"),
    ("reply", "Auto-Reply", "Low"),
    ("return", "Return/Undeliverable", "Low"),
    ("spam", "Spam Reporting", "Medium"),
    ("complaint", "Complaints", "High"),
    ("compaint", "Complaints", "High"),
    ("complaints", "Complaints", "High"),
    ("director", "Director", "High"),
    ("ceo", "CEO", "High"),
    ("cfo", "CFO", "High"),
    ("cto", "CTO", "High"),
    ("coo", "COO", "High"),
    ("vp", "Vice President", "High"),
    ("president", "President", "High"),
    ("owner", "Owner", "High"),
    ("founder", "Founder", "High"),
    ("manager", "Manager", "Medium"),
    ("editor", "Editor", "Medium"),
    ("writer", "Writer", "Low"),
    ("contributor", "Contributor", "Low"),
    ("moderator", "Moderator", "Medium"),
    ("member", "Member", "Low"),
    ("user", "User Account", "Low"),
    ("payment", "Payment Processing", "High"),
    ("payments", "Payment Processing", "High"),
    ("invoice", "Invoicing", "High"),
    ("accounting", "Accounting", "High"),
    ("finance", "Finance", "High"),
    ("accounts", "Accounts", "High"),
    ("orders", "Orders", "Medium"),
    ("shipping", "Shipping", "Medium"),
    ("dispatch", "Dispatch", "Medium"),
    ("delivery", "Delivery", "Medium"),
    ("returns", "Returns", "Medium"),
    ("store", "Store", "Medium"),
    ("shop", "Shop", "Medium"),
    ("service", "Customer Service", "Medium"),
    ("services", "Services", "Medium"),
    ("customer", "Customer Relations", "Medium"),
    ("customers", "Customer Relations", "Medium"),
    ("client", "Client Relations", "Medium"),
    ("clients", "Client Relations", "Medium"),
    ("vendor", "Vendor Relations", "Medium"),
    ("vendors", "Vendor Relations", "Medium"),
    ("supplier", "Supplier Relations", "Medium"),
    ("suppliers", "Supplier Relations", "Medium"),
    ("product", "Product Team", "Medium"),
    ("products", "Product Team", "Medium"),
    ("quote", "Quotations", "Medium"),
    ("quotes", "Quotations", "Medium"),
    ("order", "Orders", "Medium"),
    ("booking", "Bookings", "Medium"),
    ("bookings", "Bookings", "Medium"),
    ("reservation", "Reservations", "Medium"),
    ("reservations", "Reservations", "Medium"),
    ("ticket", "Support Ticket", "Medium"),
    ("tickets", "Support Tickets", "Medium"),
    ("request", "Requests", "Medium"),
    ("requests", "Requests", "Medium"),
    ("idea", "Ideas/Suggestions", "Low"),
    ("ideas", "Ideas/Suggestions", "Low"),
    ("suggestion", "Suggestions", "Low"),
    ("suggestions", "Suggestions", "Low"),
    ("social", "Social Media", "Medium"),
    ("fb", "Facebook", "Medium"),
    ("twitter", "Twitter/X", "Medium"),
    ("instagram", "Instagram", "Medium"),
    ("linkedin", "LinkedIn", "Medium"),
    ("youtube", "YouTube", "Medium"),
    ("telegram", "Telegram", "Medium"),
    ("whatsapp", "WhatsApp", "Medium"),
    ("messenger", "Messenger", "Medium"),
    ("email", "Email Admin", "Medium"),
    ("correspondence", "Correspondence", "Medium"),
    ("communication", "Communications", "Medium"),
    ("communications", "Communications", "Medium"),
    ("travel", "Travel", "Medium"),
    ("trips", "Trips", "Medium"),
    ("expense", "Expenses", "Medium"),
    ("expenses", "Expenses", "Medium"),
    ("benefits", "Benefits", "Medium"),
    ("payroll", "Payroll", "High"),
    ("training", "Training", "Medium"),
    ("learning", "Learning/Education", "Medium"),
    ("compliance", "Compliance", "High"),
    ("audit", "Audit", "High"),
    ("audits", "Audits", "High"),
    ("risk", "Risk Management", "High"),
    ("insurance", "Insurance", "High"),
    ("quality", "Quality Assurance", "Medium"),
    ("qa", "Quality Assurance", "Medium"),
    ("testing", "Testing", "Medium"),
    ("release", "Release Management", "Medium"),
    ("deploy", "Deployment", "Low"),
    ("backup", "Backup Systems", "Medium"),
    ("backups", "Backup Systems", "Medium"),
]

PATTERN_TYPES = re.compile(r"^[a-zA-Z][a-zA-Z0-9._-]*$")

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    email = target.strip().lower()
    if "@" not in email:
        findings.append(make_finding(
            entity="Not a valid email",
            ftype="Role Detection Error",
            source="EmailRoleDetector",
            confidence="High", color="red", category="General OSINT",
            threat_level="Informational", status="Error",
            tags=["error"]
        ))
        return findings

    local_part = email.split("@")[0]
    domain = email.split("@")[1]

    if not PATTERN_TYPES.match(local_part):
        findings.append(make_finding(
            entity=f"Local part '{local_part}' contains unusual characters",
            ftype="Unusual Local Part",
            source="EmailRoleDetector",
            confidence="High", color="orange", category="Email Analysis",
            threat_level="Elevated Risk", status="Unusual",
            tags=["local-part", "unusual"]
        ))

    matched_roles = []
    for pattern, description, sensitivity in ROLE_PATTERNS:
        if local_part == pattern:
            matched_roles.append((pattern, description, sensitivity))

    if matched_roles:
        for pattern, description, sensitivity in matched_roles:
            color_map = {"High": "red", "Medium": "orange", "Low": "slate"}
            sev_map = {"High": "Elevated Risk", "Medium": "Standard Target", "Low": "Informational"}
            findings.append(make_finding(
                entity=f"ROLE ACCOUNT: {email} matches '{pattern}' ({description})",
                type="Role-Based Email Detected",
                source="EmailRoleDetector",
                confidence="High",
                color=color_map.get(sensitivity, "orange"),
                category="Email Risk Intelligence",
                threat_level=sev_map.get(sensitivity, "Elevated Risk"),
                status=f"Role: {description}",
                resolution=f"Pattern: {pattern}, Sensitivity: {sensitivity}",
                raw_data=f"Email: {email} | Local: {local_part} | Pattern: {pattern} | Role: {description} | Sensitivity: {sensitivity}",
                tags=["role-based", "generic-account", pattern, sensitivity.lower(), domain]
            ))
    else:
        findings.append(make_finding(
            entity=f"No role pattern match for {local_part}",
            ftype="No Role Detected",
            source="EmailRoleDetector",
            confidence="High",
            color="emerald",
            category="Email Analysis",
            threat_level="Informational",
            status="Personal/Unique",
            tags=["role-based", "personal-account"]
        ))

    prefix_matches = []
    for pattern, description, sensitivity in ROLE_PATTERNS:
        if local_part.startswith(pattern + ".") or local_part.startswith(pattern + "-") or local_part.startswith(pattern + "_"):
            prefix_matches.append((pattern, description, sensitivity))

    for pattern, description, sensitivity in prefix_matches:
        suffix = local_part.replace(pattern, "", 1).lstrip(".-_")
        findings.append(make_finding(
            entity=f"PREFIX MATCH: {email} starts with '{pattern}' (+ suffix '{suffix}')",
            type="Role-Prefix Email Detected",
            source="EmailRoleDetector",
            confidence="Medium",
            color="orange",
            category="Email Risk Intelligence",
            threat_level="Elevated Risk",
            status=f"Role Prefix: {description}",
            tags=["role-based", "prefix-match", pattern, description.lower().replace(" ", "-")]
        ))

    suffix_matches = []
    for pattern, description, sensitivity in ROLE_PATTERNS:
        if local_part.endswith("." + pattern) or local_part.endswith("-" + pattern) or local_part.endswith("_" + pattern):
            suffix_matches.append((pattern, description, sensitivity))

    for pattern, description, sensitivity in suffix_matches:
        findings.append(make_finding(
            entity=f"SUFFIX MATCH: {email} ends with '{pattern}'",
            ftype="Role-Suffix Email Detected",
            source="EmailRoleDetector",
            confidence="Medium",
            color="orange",
            category="Email Risk Intelligence",
            threat_level="Elevated Risk",
            status=f"Role Suffix: {description}",
            tags=["role-based", "suffix-match", pattern]
        ))

    all_role_matches = matched_roles + prefix_matches + suffix_matches
    role_count = len(all_role_matches)

    high_sensitivity_count = sum(1 for _, _, s in all_role_matches if s == "High")
    med_sensitivity_count = sum(1 for _, _, s in all_role_matches if s == "Medium")

    if role_count > 0:
        findings.append(make_finding(
            entity=f"Role Analysis: {role_count} pattern match(es) for {email}",
            type="Role Detection Summary",
            source="EmailRoleDetector",
            confidence="High",
            color="orange" if high_sensitivity_count > 0 else "yellow",
            category="Email Risk Intelligence",
            threat_level="Elevated Risk" if high_sensitivity_count > 0 else "Standard Target",
            status=f"{role_count} matches, {high_sensitivity_count} high sensitivity",
            raw_data=f"Total matches: {role_count} | High: {high_sensitivity_count} | Medium: {med_sensitivity_count} | Patterns: {', '.join(p for p, _, _ in all_role_matches)}",
            tags=["role-based", "summary", email]
        ))
    else:
        findings.append(make_finding(
            entity=f"No role patterns matched local part '{local_part}'",
            ftype="Role Detection Summary",
            source="EmailRoleDetector",
            confidence="High",
            color="emerald",
            category="Email Analysis",
            threat_level="Informational",
            status="No Role Patterns",
            tags=["role-based", "summary", "clean"]
        ))

    found_role = any(p == local_part for p, _, _ in ROLE_PATTERNS)

    findings.append(make_finding(
        entity=f"Email classification: {'ROLE/GENERIC' if found_role else 'PERSONAL/UNIQUE'}",
        ftype="Email Type Classification",
        source="EmailRoleDetector",
        confidence="High",
        color="red" if found_role else "emerald",
        category="Email Analysis",
        threat_level="Elevated Risk" if found_role else "Informational",
        status="Role Account" if found_role else "Personal Account",
        raw_data=f"Email: {email} | Local: {local_part} | Domain: {domain} | Role: {found_role} | Description: {', '.join(d for p,d,s in matched_roles)}",
        tags=["classification", "email-type"]
    ))

    findings.append(make_finding(
        entity=f"Checked {email} against {len(ROLE_PATTERNS)} role patterns",
        type="Role Pattern Coverage",
        source="EmailRoleDetector",
        confidence="High",
        color="slate",
        category="General OSINT",
        threat_level="Informational",
        status="Complete",
        tags=["coverage", "role-patterns"]
    ))

    recommendations = []
    if found_role:
        recommendations.append("Role-based emails are more likely to receive spam and targeted attacks")
        recommendations.append("Consider using individual email addresses instead of role accounts")
        recommendations.append("Role accounts make social engineering easier by identifying departmental contacts")
    else:
        recommendations.append("Using a unique local part reduces spam and targeted attack surface")

    for i, rec in enumerate(recommendations):
        findings.append(make_finding(
            entity=f"Recommendation {i+1}: {rec[:100]}",
            ftype="Role-Based Email Recommendation",
            source="EmailRoleDetector",
            confidence="Medium",
            color="orange",
            category="Security Recommendation",
            threat_level="Informational",
            tags=["recommendation", "role-based", "security-tip"]
        ))

    return findings
