"""
Tech Stack Detector - Identify frameworks, CMS, and technologies
"""
import requests
import re
from bs4 import BeautifulSoup
import json
import click


class TechStackDetector:
    """Detect web technologies from headers and HTML"""
    
    TECH_PATTERNS = {
        # CMS
        'WordPress': [r'wp-content', r'wp-includes', r'wordpress', r'wp-json'],
        'Drupal': [r'drupal', r'/sites/default', r'sites/all'],
        'Joomla': [r'joomla', r'/components/', r'/modules/'],
        'Magento': [r'magento', r'/app/design', r'/skin/'],
        'Shopify': [r'shopify', r'cdn.shopify.com'],
        
        # Frameworks
        'Laravel': [r'laravel', r'laravel-app', r'/app/'],
        'Django': [r'django', r'/static/admin'],
        'Flask': [r'flask'],
        'React': [r'react', r'/__/firebase', r'/static/js'],
        'Vue': [r'vue\.js', r'nuxt'],
        'Angular': [r'angular', r'/ng-'],
        'ASP.NET': [r'asp\.net', r'\.aspx', r'__VIEWSTATE'],
        
        # Servers
        'Apache': [r'apache'],
        'Nginx': [r'nginx'],
        'IIS': [r'IIS'],
        'Tomcat': [r'tomcat'],
        
        # Languages
        'PHP': [r'\.php', r'x-powered-by.*php'],
        'Java': [r'jsessionid', r'java'],
        'Python': [r'python'],
        'Node.js': [r'node\.js', r'express'],
    }
    
    HEADER_INDICATORS = {
        'X-Powered-By': 'Server Tech',
        'Server': 'Server',
        'X-AspNet-Version': 'ASP.NET Version',
        'X-Runtime': 'Framework',
    }
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def detect_from_headers(self, url: str) -> dict:
        """Detect tech from HTTP headers"""
        try:
            response = self.session.head(url, timeout=self.timeout, allow_redirects=True)
            headers = response.headers
            
            indicators = {}
            for header, label in self.HEADER_INDICATORS.items():
                if header in headers:
                    indicators[label] = headers[header]
            
            return indicators
        except Exception as e:
            return {"error": str(e)}
    
    def detect_from_html(self, url: str) -> dict:
        """Detect tech from HTML content"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            html = response.text
            
            detected = {}
            for tech, patterns in self.TECH_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, html, re.IGNORECASE):
                        detected[tech] = True
                        break
            
            # Parse HTML for more info
            soup = BeautifulSoup(html, 'html.parser')
            
            # Check meta tags
            generator = soup.find('meta', attrs={'name': 'generator'})
            if generator:
                detected['Generator'] = generator.get('content', 'Unknown')
            
            return detected
        except Exception as e:
            return {"error": str(e)}
    
    def full_scan(self, url: str) -> dict:
        """Full technology scan"""
        headers_tech = self.detect_from_headers(url)
        html_tech = self.detect_from_html(url)
        
        return {
            "url": url,
            "headers": headers_tech,
            "html": html_tech
        }


@click.command()
@click.option('--url', required=True, help='Target URL')
@click.option('--output', default=None, help='Save results to JSON')
def detect_tech(url, output):
    """Detect web technologies and frameworks"""
    
    detector = TechStackDetector()
    
    click.echo(f"[*] Detecting technologies for {url}")
    results = detector.full_scan(url)
    
    click.echo("\n[+] Headers Analysis:")
    for key, value in results['headers'].items():
        click.echo(f"    {key}: {value}")
    
    click.echo("\n[+] HTML Content Analysis:")
    if 'error' not in results['html']:
        for tech in sorted(results['html'].keys()):
            if tech != 'Generator':
                click.echo(f"    [✓] {tech}")
        
        if 'Generator' in results['html']:
            click.echo(f"    Generator: {results['html']['Generator']}")
    
    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        click.echo(f"\n[+] Results saved to {output}")


if __name__ == "__main__":
    detect_tech()
