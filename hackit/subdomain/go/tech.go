package main

import (
	"net/http"
	"strings"
)

// detectTech identifies technologies used by the target
func detectTech(headers http.Header, body string) []string {
	var techs []string

	// Headers Analysis
	if server := headers.Get("Server"); server != "" {
		techs = append(techs, server)
	}
	if powered := headers.Get("X-Powered-By"); powered != "" {
		techs = append(techs, "PoweredBy:"+powered)
	}
	if generator := headers.Get("X-Generator"); generator != "" {
		techs = append(techs, "Generator:"+generator)
	}
	if aspVer := headers.Get("X-AspNet-Version"); aspVer != "" {
		techs = append(techs, "ASP.NET:"+aspVer)
	}

	// Body Analysis (CMS & Frameworks)
	bodyLower := strings.ToLower(body)

	// CMS
	if strings.Contains(bodyLower, "wp-content") || strings.Contains(bodyLower, "wp-includes") {
		techs = append(techs, "WordPress")
	}
	if strings.Contains(bodyLower, "joomla") {
		techs = append(techs, "Joomla")
	}
	if strings.Contains(bodyLower, "drupal") {
		techs = append(techs, "Drupal")
	}
	if strings.Contains(bodyLower, "magento") {
		techs = append(techs, "Magento")
	}
	if strings.Contains(bodyLower, "shopify") {
		techs = append(techs, "Shopify")
	}

	// Frameworks
	if strings.Contains(bodyLower, "laravel") {
		techs = append(techs, "Laravel")
	}
	if strings.Contains(bodyLower, "django") {
		techs = append(techs, "Django")
	}
	if strings.Contains(bodyLower, "react") || strings.Contains(bodyLower, "react-dom") {
		techs = append(techs, "React")
	}
	if strings.Contains(bodyLower, "vue.js") || strings.Contains(bodyLower, "vuejs") {
		techs = append(techs, "Vue.js")
	}
	if strings.Contains(bodyLower, "angular") {
		techs = append(techs, "Angular")
	}
	if strings.Contains(bodyLower, "bootstrap") {
		techs = append(techs, "Bootstrap")
	}
	if strings.Contains(bodyLower, "jquery") {
		techs = append(techs, "jQuery")
	}

	// Server/Infrastructure (Body check if header missing)
	if strings.Contains(bodyLower, "nginx") {
		techs = append(techs, "Nginx")
	}
	if strings.Contains(bodyLower, "apache") {
		techs = append(techs, "Apache")
	}
	if strings.Contains(bodyLower, "cloudflare") {
		techs = append(techs, "Cloudflare")
	}
	if strings.Contains(bodyLower, "firebase") {
		techs = append(techs, "Firebase")
	}
	if strings.Contains(bodyLower, "sentry.io") {
		techs = append(techs, "Sentry")
	}
	if strings.Contains(bodyLower, "google-analytics.com") || strings.Contains(bodyLower, "googletagmanager.com") {
		techs = append(techs, "Google Analytics")
	}
	if strings.Contains(bodyLower, "netlify") {
		techs = append(techs, "Netlify")
	}
	if strings.Contains(bodyLower, "vercel") {
		techs = append(techs, "Vercel")
	}
	if strings.Contains(bodyLower, "heroku") {
		techs = append(techs, "Heroku")
	}

	return unique(techs)
}
