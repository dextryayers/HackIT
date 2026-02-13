import requests
from bs4 import BeautifulSoup
import re
import sys
import json
import argparse
from urllib.parse import urljoin, urlparse

class SmartAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.found_endpoints = set()
        self.tech_stack = []

    def detect_tech(self):
        print(f"[*] Detecting technology for {self.target_url}...")
        try:
            resp = requests.get(self.target_url, timeout=10, verify=False)
            headers = resp.headers
            
            # Simple header-based detection
            if 'X-Powered-By' in headers:
                self.tech_stack.append(headers['X-Powered-By'])
            if 'Server' in headers:
                self.tech_stack.append(f"Server: {headers['Server']}")
            
            # Content-based detection
            soup = BeautifulSoup(resp.text, 'html.parser')
            if soup.find('meta', {'name': 'generator'}):
                self.tech_stack.append(f"Generator: {soup.find('meta', {'name': 'generator'})['content']}")
            
            if 'wp-content' in resp.text:
                self.tech_stack.append("WordPress")
            if 'laravel_session' in resp.cookies:
                self.tech_stack.append("Laravel")
                
            print(f"[+] Tech Stack: {', '.join(self.tech_stack) if self.tech_stack else 'Unknown'}")
        except Exception as e:
            print(f"[!] Tech detection failed: {e}")

    def extract_js_endpoints(self):
        print(f"[*] Extracting endpoints from JavaScript...")
        try:
            resp = requests.get(self.target_url, timeout=10, verify=False)
            soup = BeautifulSoup(resp.text, 'html.parser')
            scripts = soup.find_all('script', src=True)
            
            for script in scripts:
                js_url = urljoin(self.target_url, script['src'])
                js_resp = requests.get(js_url, timeout=5, verify=False)
                # Regex to find potential endpoints in JS
                endpoints = re.findall(r'["\'](/[a-zA-Z0-9\._\-/]+)["\']', js_resp.text)
                for ep in endpoints:
                    if len(ep) > 1 and not ep.startswith('//'):
                        self.found_endpoints.add(ep)
            
            print(f"[+] Found {len(self.found_endpoints)} potential endpoints from JS.")
        except Exception as e:
            print(f"[!] JS extraction failed: {e}")

    def detect_waf(self):
        print(f"[*] Checking for WAF (Web Application Firewall)...")
        waf_payloads = ["<script>alert(1)</script>", "../../../etc/passwd", "' OR 1=1 --"]
        for payload in waf_payloads:
            try:
                resp = requests.get(self.target_url, params={"test": payload}, timeout=5, verify=False)
                if resp.status_code in [403, 406, 501]:
                    server = resp.headers.get('Server', '').lower()
                    if 'cloudflare' in server:
                        return "Cloudflare"
                    if 'fortiweb' in server:
                        return "FortiWeb"
                    if 'akamai' in resp.text.lower():
                        return "Akamai"
                    return "Generic WAF (Blocked Payload)"
            except:
                continue
        return "None Detected"

    def find_backups(self):
        print(f"[*] Scanning for common backup files...")
        backups = [".zip", ".tar.gz", ".rar", ".7z", ".bak", ".old", ".sql"]
        base_name = urlparse(self.target_url).netloc.split('.')[0]
        potential_files = [f"/{base_name}{ext}" for ext in backups]
        potential_files += [f"/backup{ext}" for ext in backups]
        potential_files += [f"/www{ext}" for ext in backups]
        
        for f in potential_files:
            try:
                resp = requests.head(urljoin(self.target_url, f), timeout=3, verify=False)
                if resp.status_code == 200:
                    self.found_endpoints.add(f)
            except:
                continue

    def run(self):
        waf = self.detect_waf()
        print(f"[+] WAF: {waf}")
        self.detect_tech()
        self.find_backups()
        self.extract_js_endpoints()
        return {
            "waf": waf,
            "tech": self.tech_stack,
            "endpoints": list(self.found_endpoints)
        }

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True)
    args = parser.parse_args()
    
    analyzer = SmartAnalyzer(args.url)
    results = analyzer.run()
    # In a real scenario, we might save this to a file for Go to read
    with open("smart_analysis.json", "w") as f:
        json.dump(results, f)
