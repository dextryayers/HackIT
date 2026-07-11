import httpx
import asyncio
import re
import json
from module_common import safe_fetch, safe_fetch_json, make_finding, resolve_ip, is_ip
from models import IntelligenceFinding

AWS_SERVICES = {
    "EC2": ["compute.amazonaws.com", "ec2-", ".ec2.internal", "amazonaws.com"],
    "S3": ["s3.amazonaws.com", "s3-", "s3.us-", "s3-website", "s3.dualstack"],
    "CloudFront": ["cloudfront.net", "d1", "d2", "d3"],
    "Route53": ["awsdns-", "route53"],
    "ELB": ["elb.amazonaws.com", "elb-", "amazonaws.com"],
    "API Gateway": ["execute-api.", "api-gateway", "amazonaws.com"],
    "Lambda": ["lambda.amazonaws.com", "lambda-url", "amazonaws.com"],
    "RDS": ["rds.amazonaws.com", "rds-", "amazonaws.com"],
    "DynamoDB": ["dynamodb.amazonaws.com", "dynamodb-", "amazonaws.com"],
    "ECS": ["ecs.amazonaws.com", "ecs-", "amazonaws.com"],
    "EKS": ["eks.amazonaws.com", "eks-", "amazonaws.com"],
    "ElastiCache": ["elasticache.amazonaws.com", "elasticache-"],
    "SQS": ["sqs.amazonaws.com", "sqs-"],
    "SNS": ["sns.amazonaws.com", "sns-"],
    "WAF": ["waf.amazonaws.com", "waf-", "awswaf"],
    "ACM": ["acm.amazonaws.com"],
    "KMS": ["kms.amazonaws.com"],
    "Secrets Manager": ["secretsmanager.amazonaws.com"],
}

AWS_REGION_IPS = {
    "us-east-1": [("3.0.0.0", "3.31.255.255"), ("52.0.0.0", "52.31.255.255")],
    "us-west-2": [("44.192.0.0", "44.223.255.255"), ("52.32.0.0", "52.47.255.255")],
    "eu-west-1": [("54.72.0.0", "54.79.255.255"), ("63.32.0.0", "63.35.255.255")],
    "eu-central-1": [("18.192.0.0", "18.197.255.255"), ("35.156.0.0", "35.159.255.255")],
    "ap-southeast-1": [("13.250.0.0", "13.251.255.255"), ("46.137.0.0", "46.137.255.255")],
    "ap-northeast-1": [("13.112.0.0", "13.113.255.255"), ("52.68.0.0", "52.69.255.255")],
}

AWS_HEADER_SIGS = ["x-amz-", "x-amc-", "x-aws-", "amzn", "aws-"]

COMMON_BUCKET_NAMES = [
    "assets", "backup", "data", "files", "media", "public", "static", "uploads",
    "config", "logs", "docs", "images", "cache", "cdn", "archive", "bucket",
    "downloads", "resources", "storage", "temp", "tmp", "terraform", "state",
    "tfstate", "k8s", "kubernetes", "docker", "lambda", "functions",
]

S3_BUCKET_CHECK_URLS = [
    "https://{name}.s3.amazonaws.com",
    "https://s3.amazonaws.com/{name}",
    "https://{name}.s3.us-east-1.amazonaws.com",
    "https://{name}.s3.us-west-2.amazonaws.com",
    "https://{name}.s3.eu-west-1.amazonaws.com",
    "https://{name}.s3.eu-central-1.amazonaws.com",
    "https://{name}.s3.ap-southeast-1.amazonaws.com",
    "https://{name}.s3-website-us-east-1.amazonaws.com",
]

CLOUDFRONT_DOMAINS = [
    "cloudfront.net", "s3.amazonaws.com", "s3.us-east-1.amazonaws.com",
    "s3-website-us-east-1.amazonaws.com", "s3-website-us-west-2.amazonaws.com",
]

WAF_HEADERS = ["x-amzn-waf", "x-amz-waf", "waf-"]

ALB_PATTERNS = ["elb.amazonaws.com", "internal-elb", "loadbalancer"]

ROUTE53_PATTERNS = ["awsdns-", "route53"]

async def _resolve_target(target: str) -> tuple:
    t = target.strip()
    if is_ip(t):
        return t, True
    ip = resolve_ip(t)
    if ip:
        return ip, False
    return None, "DNS resolution failed"

async def _check_ip_ranges(ip: str) -> list:
    findings = []
    try:
        parts = ip.split(".")
        ip_int = (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    except Exception:
        return findings
    aws_ranges = [
        (("13.0.0.0", "13.255.255.255"), "AWS Global"),
        (("15.0.0.0", "15.255.255.255"), "AWS Global"),
        (("16.0.0.0", "16.255.255.255"), "AWS Global"),
        (("18.0.0.0", "18.255.255.255"), "AWS Global"),
        (("35.0.0.0", "35.183.255.255"), "AWS Global"),
        (("44.192.0.0", "44.255.255.255"), "AWS Global"),
        (("52.0.0.0", "52.255.255.255"), "AWS Global"),
        (("54.0.0.0", "54.255.255.255"), "AWS Global"),
        (("3.0.0.0", "3.255.255.255"), "AWS Global"),
        (("99.0.0.0", "99.255.255.255"), "AWS Global"),
        (("56.0.0.0", "56.255.255.255"), "AWS Global"),
        (("63.0.0.0", "63.255.255.255"), "AWS Global"),
        (("12.0.0.0", "12.255.255.255"), "AWS Global"),
    ]
    for (s, e), region in aws_ranges:
        try:
            sp = s.split("."); ep = e.split(".")
            si = (int(sp[0])<<24)+(int(sp[1])<<16)+(int(sp[2])<<8)+int(sp[3])
            ei = (int(ep[0])<<24)+(int(ep[1])<<16)+(int(ep[2])<<8)+int(ep[3])
            if si <= ip_int <= ei:
                findings.append(make_finding(
                    entity=f"AWS {region}",
                    type="AWS IP Range Match",
                    source="AWSCloudScanner",
                    confidence="High",
                    color="orange",
                    category="Cloud / Infrastructure OSINT",
                    threat_level="Informational",
                    status="Verified",
                    resolution=ip,
                    raw_data=f"IP {ip} is within AWS range {s}-{e} ({region})",
                    tags=["cloud", "aws", region.lower().replace(" ", "-")]
                ))
                break
        except Exception:
            continue
    for region, ranges in AWS_REGION_IPS.items():
        for (s, e) in ranges:
            try:
                sp = s.split("."); ep = e.split(".")
                si = (int(sp[0])<<24)+(int(sp[1])<<16)+(int(sp[2])<<8)+int(sp[3])
                ei = (int(ep[0])<<24)+(int(ep[1])<<16)+(int(ep[2])<<8)+int(ep[3])
                if si <= ip_int <= ei:
                    findings.append(make_finding(
                        entity=f"AWS Region: {region}",
                        type="AWS Region Detected (IP)",
                        source="AWSCloudScanner",
                        confidence="High",
                        color="blue",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Detected",
                        resolution=ip,
                        raw_data=f"IP {ip} maps to AWS region {region}",
                        tags=["cloud", "aws", "region", region]
                    ))
                    break
            except Exception:
                continue
    return findings

async def _check_dns_services(target: str) -> list:
    findings = []
    try:
        loop = asyncio.get_event_loop()
        try:
            answers = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'CNAME'))
            for r in answers:
                cname = str(r.target).rstrip('.').lower()
                for svc, patterns in AWS_SERVICES.items():
                    for pat in patterns:
                        if pat in cname:
                            findings.append(make_finding(
                                entity=f"AWS {svc}",
                                type="AWS Service (CNAME)",
                                source="AWSCloudScanner",
                                confidence="High",
                                color="purple",
                                category="Cloud / Infrastructure OSINT",
                                threat_level="Informational",
                                status="Detected",
                                resolution=cname,
                                raw_data=f"CNAME: {cname} matches AWS {svc} pattern '{pat}'",
                                tags=["cloud", "aws", svc.lower().replace(" ", "-")]
                            ))
                            break
        except Exception:
            pass
        try:
            answers_ns = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'NS'))
            for r in answers_ns:
                ns = str(r.target).rstrip('.').lower()
                for pat in ROUTE53_PATTERNS:
                    if pat in ns:
                        findings.append(make_finding(
                            entity="AWS Route53",
                            type="AWS DNS Service (NS)",
                            source="AWSCloudScanner",
                            confidence="High",
                            color="blue",
                            category="Cloud / Infrastructure OSINT",
                            threat_level="Informational",
                            status="Detected",
                            resolution=ns,
                            raw_data=f"NS record {ns} indicates AWS Route53",
                            tags=["cloud", "aws", "route53"]
                        ))
                        break
        except Exception:
            pass
        try:
            answers_txt = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'TXT'))
            for r in answers_txt:
                txt = str(r).lower()
                if "amazonses" in txt:
                    findings.append(make_finding(
                        entity="AWS SES",
                        type="AWS Service (TXT)",
                        source="AWSCloudScanner",
                        confidence="High",
                        color="blue",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Detected",
                        raw_data=f"TXT record indicates AWS SES: {txt[:100]}",
                        tags=["cloud", "aws", "ses"]
                    ))
                if "_amazonses" in txt or "amazon.com" in txt:
                    findings.append(make_finding(
                        entity="AWS Domain Verification",
                        type="AWS Domain (TXT)",
                        source="AWSCloudScanner",
                        confidence="Medium",
                        color="slate",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Detected",
                        raw_data=f"TXT record: {txt[:100]}",
                        tags=["cloud", "aws", "domain-verification"]
                    ))
        except Exception:
            pass
    except Exception:
        pass
    return findings

async def _analyze_headers(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    base = f"https://{target}" if not target.startswith("http") else target
    try:
        resp = await safe_fetch(client, base, follow_redirects=True, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        headers = dict(resp.headers)
        server = headers.get("server", "").lower()
        via = headers.get("via", "").lower()
        x_powered = headers.get("x-powered-by", "").lower()
        all_vals = " ".join(str(v).lower() for v in headers.values())

        if "cloudfront" in server or "cloudfront" in all_vals or "x-amz-cf-id" in headers:
            findings.append(make_finding(
                entity="AWS CloudFront",
                type="AWS Service (Header)",
                source="AWSCloudScanner",
                confidence="High",
                color="orange",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Active",
                raw_data=f"CloudFront detected via header. Server: {server}",
                tags=["cloud", "aws", "cloudfront"]
            ))
        if "amazons3" in server or "x-amz-request-id" in headers or "x-amz-id-2" in headers:
            findings.append(make_finding(
                entity="AWS S3",
                type="AWS Service (Header)",
                source="AWSCloudScanner",
                confidence="High",
                color="orange",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Active",
                raw_data=f"S3 detected via header. Server: {server}",
                tags=["cloud", "aws", "s3"]
            ))
        if "amazon" in server or "amzn" in server:
            findings.append(make_finding(
                entity="AWS (Server Header)",
                type="AWS Infrastructure",
                source="AWSCloudScanner",
                confidence="High",
                color="orange",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                raw_data=f"Server header: {server}",
                tags=["cloud", "aws"]
            ))
        if "x-amzn-requestid" in headers or "x-amzn-ErrorType" in headers:
            findings.append(make_finding(
                entity="AWS API Gateway / ALB",
                type="AWS Service (Header)",
                source="AWSCloudScanner",
                confidence="High",
                color="purple",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                raw_data="x-amzn-* headers detected indicating AWS API Gateway or ALB",
                tags=["cloud", "aws", "api-gateway"]
            ))
        if "x-amz-request-id" in headers:
            findings.append(make_finding(
                entity="AWS S3 / API Gateway",
                type="AWS Service (Header)",
                source="AWSCloudScanner",
                confidence="Medium",
                color="slate",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Suspected",
                raw_data="x-amz-request-id header present",
                tags=["cloud", "aws"]
            ))
        if "x-amz-cf-pop" in headers:
            pop = headers.get("x-amz-cf-pop", "")
            findings.append(make_finding(
                entity=f"CloudFront POP: {pop}",
                type="AWS CloudFront Edge",
                source="AWSCloudScanner",
                confidence="High",
                color="blue",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                resolution=pop,
                raw_data=f"CloudFront edge location: {pop}",
                tags=["cloud", "aws", "cloudfront", "edge"]
            ))
        if "x-amz-cf-id" in headers:
            cf_id = headers.get("x-amz-cf-id", "")
            findings.append(make_finding(
                entity=f"CloudFront ID: {cf_id[:30]}",
                type="AWS CloudFront Request",
                source="AWSCloudScanner",
                confidence="High",
                color="blue",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Identified",
                resolution=cf_id[:50],
                raw_data=f"CloudFront request ID: {cf_id}",
                tags=["cloud", "aws", "cloudfront"]
            ))
        if "x-amz-region" in headers:
            region = headers.get("x-amz-region", "")
            findings.append(make_finding(
                entity=f"AWS Region: {region}",
                type="AWS Region (Header)",
                source="AWSCloudScanner",
                confidence="High",
                color="blue",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                resolution=region,
                raw_data=f"AWS region from header: {region}",
                tags=["cloud", "aws", "region", region]
            ))
        if "x-amz-bucket-region" in headers:
            region = headers.get("x-amz-bucket-region", "")
            findings.append(make_finding(
                entity=f"S3 Bucket Region: {region}",
                type="AWS S3 Region",
                source="AWSCloudScanner",
                confidence="High",
                color="blue",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                resolution=region,
                raw_data=f"S3 bucket region: {region}",
                tags=["cloud", "aws", "s3", region]
            ))
        html = resp.text[:50000].lower() if hasattr(resp, "text") else ""
        if "amazonaws" in html or "aws-" in html or "s3." in html:
            findings.append(make_finding(
                entity="AWS (HTML Indicator)",
                type="AWS Cloud (HTML)",
                source="AWSCloudScanner",
                confidence="Medium",
                color="slate",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Suspected",
                raw_data="AWS-related content in HTML",
                tags=["cloud", "aws"]
            ))
    except Exception as e:
        findings.append(make_finding(
            entity=f"Header analysis error: {str(e)[:100]}",
            type="AWS Scan Error",
            source="AWSCloudScanner",
            confidence="Low",
            color="red",
            category="Cloud / Infrastructure OSINT",
            threat_level="Informational",
            raw_data=str(e)[:200],
            tags=["error"]
        ))
    return findings

async def _check_s3_buckets(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    base = target.split(".")[0] if "." in target else target
    base = re.sub(r"[^a-zA-Z0-9\-]", "", base).strip("-").lower()
    if not base:
        return findings
    for name_base in [base, f"{base}-data", f"{base}-assets", f"{base}-backup", f"{base}-public",
                       f"{base}-static", f"{base}-files", f"{base}-media", f"{base}-config",
                       f"{base}-logs", f"{base}-storage", f"{base}-archive", f"{base}-tmp"]:
        for tmpl in S3_BUCKET_CHECK_URLS:
            url = tmpl.format(name=name_base)
            try:
                resp = await safe_fetch(client, url, timeout=5.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    body = resp.text[:500]
                    is_listing = "<ListBucketResult" in body or "<Contents>" in body
                    findings.append(make_finding(
                        entity=f"s3://{name_base}",
                        type="AWS S3 Bucket (Public)",
                        source="AWSCloudScanner",
                        confidence="High",
                        color="red" if is_listing else "orange",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Critical" if is_listing else "Medium",
                        status="Public" + (" + Listing" if is_listing else ""),
                        resolution=url,
                        raw_data=f"Bucket {name_base} is publicly accessible at {url}. Listing: {is_listing}",
                        tags=["cloud", "aws", "s3", "bucket"]
                    ))
                    break
                elif resp.status_code == 403:
                    body = resp.text[:200]
                    if "AccessDenied" in body or "access_denied" in body.lower():
                        findings.append(make_finding(
                            entity=f"s3://{name_base}",
                            type="AWS S3 Bucket (Exists)",
                            source="AWSCloudScanner",
                            confidence="High",
                            color="yellow",
                            category="Cloud / Infrastructure OSINT",
                            threat_level="Low",
                            status="Exists (Denied)",
                            resolution=url,
                            raw_data=f"Bucket {name_base} exists but access denied",
                            tags=["cloud", "aws", "s3", "bucket"]
                        ))
                        break
            except Exception:
                continue
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    target = target.strip().lower()
    if target.startswith("http"):
        from urllib.parse import urlparse
        target = urlparse(target).netloc

    ip, is_ip = await _resolve_target(target)
    if ip is None:
        findings.append(make_finding(entity=f"DNS resolution failed: {target}", type="DNS Error", source="AWSCloudScanner", confidence="Low", color="red", category="Cloud / Infrastructure OSINT", raw_data=str(is_ip)[:200], tags=["error"]))
        return findings

    if not is_ip:
        findings.append(make_finding(
            entity=f"{target} -> {ip}",
            type="DNS Resolution",
            source="AWSCloudScanner",
            confidence="High",
            color="slate",
            category="Cloud / Infrastructure OSINT",
            threat_level="Informational",
            status="Resolved",
            resolution=ip,
            tags=["dns", "resolution"]
        ))

    ip_findings = await _check_ip_ranges(ip)
    findings.extend(ip_findings)

    dns_findings = await _check_dns_services(target)
    findings.extend(dns_findings)

    header_findings = await _analyze_headers(target, client)
    findings.extend(header_findings)

    bucket_findings = await _check_s3_buckets(target, client)
    findings.extend(bucket_findings)

    aws_services = sum(1 for f in findings if f.type in ("AWS Service (CNAME)", "AWS Service (Header)"))
    aws_infra = sum(1 for f in findings if "AWS" in f.type and "AWS" not in f.entity)
    aws_buckets = sum(1 for f in findings if "S3" in f.entity or "s3://" in f.entity)

    findings.append(make_finding(entity=f"AWS services detected: {aws_services}", type="AWS Service Count", source="AWSCloudScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["aws", "summary"]))
    findings.append(make_finding(entity=f"AWS infrastructure indicators: {aws_infra}", type="AWS Infrastructure Count", source="AWSCloudScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["aws", "summary"]))
    findings.append(make_finding(entity=f"AWS S3 buckets: {aws_buckets}", type="AWS Bucket Count", source="AWSCloudScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["aws", "summary"]))
    findings.append(make_finding(entity=f"AWS IP match: {'Yes' if any('AWS IP Range' in f.type for f in findings) else 'No'}", type="AWS Hosting Status", source="AWSCloudScanner", confidence="Medium", color="slate", category="Cloud / Infrastructure OSINT", tags=["aws", "summary"]))
    findings.append(make_finding(entity=f"Target: {target}", type="AWS Scan Target", source="AWSCloudScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", tags=["aws", "target"]))
    findings.append(make_finding(entity=f"Resolved IP: {ip}", type="AWS Resolved Address", source="AWSCloudScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", tags=["aws", "ip"]))
    findings.append(make_finding(entity=f"Total AWS findings: {len(findings)}", type="AWS Scan Summary", source="AWSCloudScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["aws", "summary"]))

    return findings
