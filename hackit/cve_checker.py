"""
CVE Checker - Fingerprint versions and match against CVE database
"""
import json
import click
import requests
import re
from typing import Dict, List, Tuple


class CVEChecker:
    """Check for known vulnerabilities"""
    
    # Local CVE database (simplified)
    # In production, you'd use a real database like NVD
    CVE_DATABASE = {
        "wordpress": {
            "5.0.0": [
                {"cve": "CVE-2019-1234", "severity": "High", "description": "Authentication bypass"},
                {"cve": "CVE-2019-5678", "severity": "Medium", "description": "XSS vulnerability"},
            ],
            "5.1.0": [
                {"cve": "CVE-2020-1234", "severity": "Critical", "description": "RCE vulnerability"},
            ],
            "5.2.0": [
                {"cve": "CVE-2020-5678", "severity": "High", "description": "SQL injection"},
            ]
        },
        "drupal": {
            "7.0.0": [
                {"cve": "CVE-2019-6340", "severity": "Critical", "description": "REST API RCE"},
            ],
            "8.0.0": [
                {"cve": "CVE-2019-6341", "severity": "High", "description": "YAML injection"},
            ],
            "9.0.0": [
                {"cve": "CVE-2021-3129", "severity": "Critical", "description": "File upload RCE"},
            ]
        },
        "apache": {
            "2.4.49": [
                {"cve": "CVE-2021-41773", "severity": "Critical", "description": "Path traversal RCE"},
            ],
            "2.4.50": [
                {"cve": "CVE-2021-42013", "severity": "Critical", "description": "Path traversal RCE"},
            ]
        },
        "nginx": {
            "1.10.0": [
                {"cve": "CVE-2017-7529", "severity": "High", "description": "Integer overflow"},
            ]
        },
        "php": {
            "7.2.0": [
                {"cve": "CVE-2019-1234", "severity": "High", "description": "Type confusion"},
            ],
            "7.4.0": [
                {"cve": "CVE-2020-1234", "severity": "Medium", "description": "Hash collision"},
            ]
        }
    }
    
    def __init__(self):
        self.session = requests.Session()
    
    def fingerprint_version(self, software: str, version: str) -> Dict:
        """Fingerprint software version"""
        software_lower = software.lower()
        
        # Exact match
        if software_lower in self.CVE_DATABASE:
            if version in self.CVE_DATABASE[software_lower]:
                vulns = self.CVE_DATABASE[software_lower][version]
                return {
                    "software": software,
                    "version": version,
                    "match_type": "exact",
                    "vulnerabilities": vulns
                }
        
        # Minor version match (e.g., 5.x for 5.0.0, 5.0.1, etc.)
        if software_lower in self.CVE_DATABASE:
            major_minor = '.'.join(version.split('.')[:2])
            for db_version in self.CVE_DATABASE[software_lower].keys():
                db_major_minor = '.'.join(db_version.split('.')[:2])
                if major_minor == db_major_minor:
                    vulns = self.CVE_DATABASE[software_lower][db_version]
                    return {
                        "software": software,
                        "version": version,
                        "match_type": "minor",
                        "close_version": db_version,
                        "vulnerabilities": vulns
                    }
        
        return {
            "software": software,
            "version": version,
            "match_type": "no_match",
            "vulnerabilities": []
        }
    
    def check_multiple_versions(self, fingerprints: List[Tuple[str, str]]) -> List[Dict]:
        """Check multiple software versions"""
        results = []
        
        for software, version in fingerprints:
            result = self.fingerprint_version(software, version)
            results.append(result)
        
        return results
    
    def get_cves_by_severity(self, results: List[Dict], severity: str = "Critical") -> List[Dict]:
        """Filter CVEs by severity"""
        critical = []
        
        for result in results:
            for vuln in result.get('vulnerabilities', []):
                if vuln['severity'] == severity:
                    critical.append({
                        "software": result['software'],
                        "version": result['version'],
                        **vuln
                    })
        
        return critical


@click.command()
@click.option('--software', required=True, help='Software name')
@click.option('--version', required=True, help='Version number')
@click.option('--severity', default=None, type=click.Choice(['Critical', 'High', 'Medium', 'Low']), 
              help='Filter by severity')
@click.option('--output', default=None, help='Save results to JSON')
def check_cve(software, version, severity, output):
    """Check for known CVEs"""
    
    checker = CVEChecker()
    
    click.echo(f"[*] Checking CVEs for {software} {version}")
    
    result = checker.fingerprint_version(software, version)
    
    vulns = result.get('vulnerabilities', [])
    
    click.echo(f"\n[+] Match type: {result['match_type']}")
    if result.get('close_version'):
        click.echo(f"[*] Close version found: {result['close_version']}")
    
    # Filter by severity if specified
    if severity:
        vulns = [v for v in vulns if v['severity'] == severity]
        click.echo(f"[*] Filtered by severity: {severity}")
    
    click.echo(f"\n[+] Vulnerabilities found: {len(vulns)}")
    
    if vulns:
        # Group by severity
        by_severity = {}
        for vuln in vulns:
            sev = vuln['severity']
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(vuln)
        
        for sev in ['Critical', 'High', 'Medium', 'Low']:
            if sev in by_severity:
                click.echo(f"\n[{'!' if sev == 'Critical' else '+'}] {sev.upper()} ({len(by_severity[sev])}):")
                for vuln in by_severity[sev]:
                    click.echo(f"    {vuln['cve']}: {vuln['description']}")
    else:
        click.echo("\n[+] No known vulnerabilities found")
    
    if output:
        with open(output, 'w') as f:
            json.dump(result, f, indent=2)
        click.echo(f"\n[+] Results saved to {output}")


if __name__ == "__main__":
    check_cve()
