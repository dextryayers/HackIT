package main

import (
	"net/http"
	"regexp"
	"strings"
)

type Signature struct {
	Name        string
	Type        string
	Pattern     *regexp.Regexp
	Location    string
	Version     int
}

var signatures = []Signature{
	// CMS
	{Name: "WordPress", Type: "cms", Pattern: regexp.MustCompile(`(?i)/wp-(content|includes|admin)/`), Location: "body"},
	{Name: "WordPress", Type: "cms", Pattern: regexp.MustCompile(`(?i)<meta name="generator" content="WordPress`), Location: "body"},
	{Name: "WordPress", Type: "cms", Pattern: regexp.MustCompile(`(?i)wp-json`), Location: "body"},
	{Name: "Drupal", Type: "cms", Pattern: regexp.MustCompile(`(?i)/sites/default/(files|themes)/`), Location: "body"},
	{Name: "Drupal", Type: "cms", Pattern: regexp.MustCompile(`(?i)Drupal\.s?js`), Location: "body"},
	{Name: "Drupal", Type: "cms", Pattern: regexp.MustCompile(`(?i)<meta name="Generator" content="Drupal`), Location: "body"},
	{Name: "Joomla", Type: "cms", Pattern: regexp.MustCompile(`(?i)/components/com_`), Location: "body"},
	{Name: "Joomla", Type: "cms", Pattern: regexp.MustCompile(`(?i)/modules/mod_`), Location: "body"},
	{Name: "Joomla", Type: "cms", Pattern: regexp.MustCompile(`(?i)<meta name="generator" content="Joomla!`), Location: "body"},

	// Frameworks
	{Name: "Laravel", Type: "framework", Pattern: regexp.MustCompile(`(?i)laravel_session`), Location: "header"},
	{Name: "Laravel", Type: "framework", Pattern: regexp.MustCompile(`(?i)X-Powered-By:.*PHP.*Laravel`), Location: "header"},
	{Name: "Django", Type: "framework", Pattern: regexp.MustCompile(`(?i)csrftoken`), Location: "header"},
	{Name: "Django", Type: "framework", Pattern: regexp.MustCompile(`(?i)sessionid`), Location: "header"},
	{Name: "Django", Type: "framework", Pattern: regexp.MustCompile(`(?i)django\.js`), Location: "body"},
	{Name: "Rails", Type: "framework", Pattern: regexp.MustCompile(`(?i)rails_session`), Location: "header"},
	{Name: "Rails", Type: "framework", Pattern: regexp.MustCompile(`(?i)X-Powered-By:.*Phusion`), Location: "header"},
	{Name: "Rails", Type: "framework", Pattern: regexp.MustCompile(`(?i)csrf-token.*content=.*"[^"]{44}==`), Location: "body"},
	{Name: "Spring", Type: "framework", Pattern: regexp.MustCompile(`(?i)X-Application-Context`), Location: "header"},
	{Name: "Spring", Type: "framework", Pattern: regexp.MustCompile(`(?i)JSESSIONID`), Location: "header"},
	{Name: "Express", Type: "framework", Pattern: regexp.MustCompile(`(?i)X-Powered-By:.*Express`), Location: "header"},
	{Name: "Flask", Type: "framework", Pattern: regexp.MustCompile(`(?i)flask_session`), Location: "header"},
	{Name: "FastAPI", Type: "framework", Pattern: regexp.MustCompile(`(?i)X-FastAPI`), Location: "header"},
	{Name: "ASP.NET", Type: "framework", Pattern: regexp.MustCompile(`(?i)X-AspNet-Version`), Location: "header"},
	{Name: "ASP.NET", Type: "framework", Pattern: regexp.MustCompile(`(?i)X-AspNetMvc-Version`), Location: "header"},
	{Name: "ASP.NET", Type: "framework", Pattern: regexp.MustCompile(`(?i)__VIEWSTATE`), Location: "body"},
	{Name: "Next.js", Type: "framework", Pattern: regexp.MustCompile(`(?i)__NEXT_DATA__`), Location: "body"},
	{Name: "Next.js", Type: "framework", Pattern: regexp.MustCompile(`(?i)/_next/static/`), Location: "body"},
	{Name: "Nuxt.js", Type: "framework", Pattern: regexp.MustCompile(`(?i)__NUXT__`), Location: "body"},
	{Name: "Gatsby", Type: "framework", Pattern: regexp.MustCompile(`(?i)___gatsby`), Location: "body"},

	// Servers
	{Name: "Nginx", Type: "server", Pattern: regexp.MustCompile(`(?i)^nginx`), Location: "server"},
	{Name: "Apache", Type: "server", Pattern: regexp.MustCompile(`(?i)^Apache`), Location: "server"},
	{Name: "IIS", Type: "server", Pattern: regexp.MustCompile(`(?i)^Microsoft-IIS`), Location: "server"},
	{Name: "Tomcat", Type: "server", Pattern: regexp.MustCompile(`(?i)^Apache-Coyote`), Location: "server"},
	{Name: "Tomcat", Type: "server", Pattern: regexp.MustCompile(`(?i)Tomcat`), Location: "header"},
	{Name: "Jetty", Type: "server", Pattern: regexp.MustCompile(`(?i)Jetty`), Location: "header"},
	{Name: "Caddy", Type: "server", Pattern: regexp.MustCompile(`(?i)^Caddy`), Location: "server"},
	{Name: "OpenResty", Type: "server", Pattern: regexp.MustCompile(`(?i)openresty`), Location: "header"},
	{Name: "Cloudflare", Type: "server", Pattern: regexp.MustCompile(`(?i)cloudflare`), Location: "header"},

	// WAF
	{Name: "Cloudflare", Type: "waf", Pattern: regexp.MustCompile(`(?i)__cfduid`), Location: "header"},
	{Name: "Cloudflare", Type: "waf", Pattern: regexp.MustCompile(`(?i)cf-ray`), Location: "header"},
	{Name: "Cloudflare", Type: "waf", Pattern: regexp.MustCompile(`(?i)cloudflare-nginx`), Location: "header"},
	{Name: "ModSecurity", Type: "waf", Pattern: regexp.MustCompile(`(?i)Mod_Security`), Location: "header"},
	{Name: "ModSecurity", Type: "waf", Pattern: regexp.MustCompile(`(?i)NOYB`), Location: "body"},
	{Name: "AWS WAF", Type: "waf", Pattern: regexp.MustCompile(`(?i)awselb`), Location: "header"},
	{Name: "AWS WAF", Type: "waf", Pattern: regexp.MustCompile(`(?i)x-amz-rid`), Location: "header"},
	{Name: "Sucuri", Type: "waf", Pattern: regexp.MustCompile(`(?i)x-sucuri`), Location: "header"},
	{Name: "Sucuri", Type: "waf", Pattern: regexp.MustCompile(`(?i)sucuri`), Location: "header"},
	{Name: "Akamai", Type: "waf", Pattern: regexp.MustCompile(`(?i)akamai`), Location: "header"},

	// Languages
	{Name: "PHP", Type: "language", Pattern: regexp.MustCompile(`(?i)X-Powered-By:.*PHP`), Location: "header"},
	{Name: "PHP", Type: "language", Pattern: regexp.MustCompile(`(?i)\.php`), Location: "body"},
	{Name: "Python", Type: "language", Pattern: regexp.MustCompile(`(?i)X-Python`), Location: "header"},
	{Name: "Ruby", Type: "language", Pattern: regexp.MustCompile(`(?i)X-Ruby`), Location: "header"},
	{Name: "Java", Type: "language", Pattern: regexp.MustCompile(`(?i)Java`), Location: "header"},
	{Name: "Node.js", Type: "language", Pattern: regexp.MustCompile(`(?i)x-powered-by:.*node`), Location: "header"},
	{Name: "Go", Type: "language", Pattern: regexp.MustCompile(`(?i)X-Go`), Location: "header"},
}

type FingerprintResult struct {
	Tech     []string
	Server   string
	CMS      string
	WAF      string
	Language string
	Framework string
}

func FingerprintResponse(resp *http.Header, body string) FingerprintResult {
	var result FingerprintResult
	headerStr := ""
	if resp != nil {
		for k, v := range *resp {
			headerStr += k + ": " + strings.Join(v, ", ") + "\n"
		}
	}
	seen := make(map[string]bool)
	server := ""
	if resp != nil {
		server = resp.Get("Server")
	}

	for _, sig := range signatures {
		var text string
		switch sig.Location {
		case "header":
			text = headerStr
		case "body":
			text = body
		case "server":
			text = server
		}
		if sig.Pattern.MatchString(text) && !seen[sig.Name+"|"+sig.Type] {
			seen[sig.Name+"|"+sig.Type] = true
			switch sig.Type {
			case "cms":
				if result.CMS == "" {
					result.CMS = sig.Name
				}
			case "waf":
				if result.WAF == "" {
					result.WAF = sig.Name
				}
			case "server":
				if result.Server == "" {
					result.Server = sig.Name
				}
			case "language":
				if result.Language == "" {
					result.Language = sig.Name
				}
			case "framework":
				result.Framework = sig.Name
			}
			result.Tech = append(result.Tech, sig.Name)
		}
	}

	if result.Server == "" && server != "" {
		result.Server = server
	}

	return result
}

func SuggestWordlistCategories(fingerprint FingerprintResult) []string {
	var cats []string
	seen := make(map[string]bool)
	catMap := map[string][]string{
		"WordPress": {"common", "php", "wordpress", "cms"},
		"Drupal":    {"common", "php", "drupal", "cms"},
		"Joomla":    {"common", "php", "joomla", "cms"},
		"Laravel":   {"common", "php", "laravel"},
		"Django":    {"common", "python", "django"},
		"Flask":     {"common", "python", "flask"},
		"Rails":     {"common", "ruby", "rails"},
		"ASP.NET":   {"common", "aspnet", "dotnet"},
		"Express":   {"common", "node", "express"},
		"Next.js":   {"common", "node", "nextjs"},
		"Nuxt.js":   {"common", "node", "nuxt"},
		"PHP":       {"common", "php"},
		"Python":    {"common", "python"},
		"Java":      {"common", "java"},
		"Node.js":   {"common", "node"},
	}

	for _, tech := range fingerprint.Tech {
		if cats, ok := catMap[tech]; ok {
			for _, c := range cats {
				if !seen[c] {
					seen[c] = true
					cats = append(cats, c)
				}
			}
		}
	}

	if _, ok := seen["common"]; !ok {
		cats = append([]string{"common"}, cats...)
	}

	return cats
}

func ExtractVersionInfo(body, header string) map[string]string {
	versions := make(map[string]string)

	patterns := map[string]*regexp.Regexp{
		"WordPress": regexp.MustCompile(`(?i)<meta name="generator" content="WordPress\s+([^"]+)"`),
		"Drupal":    regexp.MustCompile(`(?i)<meta name="Generator" content="Drupal\s+([^"]+)"`),
		"Joomla":    regexp.MustCompile(`(?i)<meta name="generator" content="Joomla!\s+([^"]+)"`),
		"PHP":       regexp.MustCompile(`(?i)X-Powered-By:.*PHP\s+([^\s,]+)`),
		"Apache":    regexp.MustCompile(`(?i)^Apache/([^\s]+)`),
		"Nginx":     regexp.MustCompile(`(?i)^nginx/([^\s]+)`),
		"IIS":       regexp.MustCompile(`(?i)^Microsoft-IIS/([^\s]+)`),
	}

	for name, re := range patterns {
		m := re.FindStringSubmatch(body + "\n" + header)
		if len(m) > 1 {
			versions[name] = m[1]
		}
	}

	return versions
}

func GenerateTechWordlists(fingerprint FingerprintResult) []string {
	var paths []string
	techPaths := map[string][]string{
		"WordPress": {"/wp-admin/", "/wp-content/", "/wp-includes/", "/wp-json/", "/xmlrpc.php", "/wp-login.php", "/wp-config.php.bak"},
		"Drupal":    {"/sites/default/", "/modules/", "/themes/", "/node/", "/user/", "/admin/"},
		"Joomla":    {"/administrator/", "/components/", "/modules/", "/templates/", "/index.php?option="},
		"Laravel":   {"/artisan", "/artisan.bak", "/.env", "/storage/", "/vendor/", "/routes/"},
		"Django":    {"/admin/", "/static/", "/api/", "/accounts/"},
		"Rails":     {"/assets/", "/rails/", "/rails/info/"},
		"ASP.NET":   {"/web.config", "/bin/", "/App_Data/", "/App_Code/"},
	}

	for _, tech := range fingerprint.Tech {
		if paths, ok := techPaths[tech]; ok {
			paths = append(paths, paths...)
		}
	}

	if len(paths) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	var unique []string
	for _, p := range paths {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}
	return unique
}
