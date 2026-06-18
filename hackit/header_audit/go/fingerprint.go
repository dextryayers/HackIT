package main

import (
	"regexp"
	"strings"
)

type FingerprintRule struct {
	Name      string
	Pattern   *regexp.Regexp
	Source    string
	Certainty string
}

var fingerprintRules = []FingerprintRule{
	{Name: "Cloudflare", Pattern: regexp.MustCompile(`cloudflare|__cfduid|cf-ray`), Source: "Server/Cookie", Certainty: "High"},
	{Name: "CloudFront", Pattern: regexp.MustCompile(`cloudfront|x-amz-`), Source: "Header", Certainty: "High"},
	{Name: "Akamai", Pattern: regexp.MustCompile(`akamai|akamaized`), Source: "Header", Certainty: "High"},
	{Name: "Fastly", Pattern: regexp.MustCompile(`fastly|x-fastly`), Source: "Header", Certainty: "High"},
	{Name: "Varnish", Pattern: regexp.MustCompile(`varnish|x-varnish`), Source: "Header", Certainty: "High"},
	{Name: "Nginx", Pattern: regexp.MustCompile(`nginx`), Source: "Server", Certainty: "High"},
	{Name: "Apache", Pattern: regexp.MustCompile(`apache`), Source: "Server", Certainty: "High"},
	{Name: "IIS", Pattern: regexp.MustCompile(`iis|microsoft-iis|x-aspnet`), Source: "Server/Header", Certainty: "High"},
	{Name: "OpenResty", Pattern: regexp.MustCompile(`openresty`), Source: "Server", Certainty: "High"},
	{Name: "PHP", Pattern: regexp.MustCompile(`php|php/`), Source: "X-Powered-By", Certainty: "High"},
	{Name: "ASP.NET", Pattern: regexp.MustCompile(`asp\.net|x-aspnet`), Source: "X-Powered-By", Certainty: "High"},
	{Name: "Node.js/Express", Pattern: regexp.MustCompile(`express`), Source: "X-Powered-By", Certainty: "Medium"},
	{Name: "Python/Django", Pattern: regexp.MustCompile(`python|django|wsgi`), Source: "Server", Certainty: "Medium"},
	{Name: "Python/Flask", Pattern: regexp.MustCompile(`flask`), Source: "Header", Certainty: "Medium"},
	{Name: "Ruby/Rails", Pattern: regexp.MustCompile(`phusion|passenger|rails|ruby`), Source: "Server/X-Powered-By", Certainty: "Medium"},
	{Name: "Java/JSP", Pattern: regexp.MustCompile(`java|jsp|servlet|tomcat|jboss|jetty`), Source: "Server/X-Powered-By", Certainty: "Medium"},
	{Name: "WordPress", Pattern: regexp.MustCompile(`wordpress`), Source: "X-Powered-By", Certainty: "Medium"},
	{Name: "Drupal", Pattern: regexp.MustCompile(`drupal`), Source: "X-Generator", Certainty: "Medium"},
	{Name: "Joomla", Pattern: regexp.MustCompile(`joomla`), Source: "X-Generator", Certainty: "Medium"},
	{Name: "Laravel", Pattern: regexp.MustCompile(`laravel`), Source: "X-Powered-By", Certainty: "Medium"},
	{Name: "Symfony", Pattern: regexp.MustCompile(`symfony|x-debug-token`), Source: "Header", Certainty: "Medium"},
	{Name: "GitHub Pages", Pattern: regexp.MustCompile(`github\.com`), Source: "Server", Certainty: "Medium"},
	{Name: "Netlify", Pattern: regexp.MustCompile(`netlify`), Source: "Server/Header", Certainty: "High"},
	{Name: "Vercel", Pattern: regexp.MustCompile(`vercel`), Source: "Server/Header", Certainty: "High"},
	{Name: "Heroku", Pattern: regexp.MustCompile(`heroku`), Source: "Server", Certainty: "High"},
	{Name: "Google Cloud", Pattern: regexp.MustCompile(`gcloud|google-cloud|gcp`), Source: "Server", Certainty: "Medium"},
	{Name: "AWS S3", Pattern: regexp.MustCompile(`amazons3|aws-s3|x-amz-`), Source: "Server/Header", Certainty: "High"},
	{Name: "AWS ELB", Pattern: regexp.MustCompile(`aws.*elb|elasticloadbalancing`), Source: "Server", Certainty: "Medium"},
}

func FingerprintTechnologies(headers map[string][]string) []TechFingerprint {
	var found []TechFingerprint
	seen := make(map[string]bool)

	allValues := ""
	for k, v := range headers {
		allValues += k + "=" + strings.Join(v, ", ") + "; "
	}

	for _, rule := range fingerprintRules {
		if seen[rule.Name] {
			continue
		}
		if rule.Pattern.MatchString(allValues) {
			found = append(found, TechFingerprint{
				Name:      rule.Name,
				Certainty: rule.Certainty,
				Source:    rule.Source,
				Version:   extractVersion(rule.Name, allValues),
			})
			seen[rule.Name] = true
		}
	}

	return found
}

var versionPatterns = map[string]*regexp.Regexp{
	"Nginx":    regexp.MustCompile(`nginx/([\d.]+)`),
	"Apache":   regexp.MustCompile(`Apache(?:/([\d.]+))?`),
	"IIS":      regexp.MustCompile(`IIS/([\d.]+)`),
	"PHP":      regexp.MustCompile(`PHP(?:/([\d.]+))?`),
	"Node.js/Express": regexp.MustCompile(`express[/\s]([\d.]+)`),
	"Cloudflare": regexp.MustCompile(`cloudflare[/\s]([\d.]+)`),
}

func extractVersion(name, allValues string) string {
	if p, ok := versionPatterns[name]; ok {
		m := p.FindStringSubmatch(allValues)
		if len(m) >= 2 && m[1] != "" {
			return m[1]
		}
	}
	return ""
}
