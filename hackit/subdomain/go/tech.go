package main

import (
	"net/http"
	"strings"
)

// detectTech identifies technologies used by the target with industrial-grade precision
func detectTech(headers http.Header, body string) []string {
	var techs []string

	// 1. Header-Based Fingerprinting (Aurat Presisi)
	server := headers.Get("Server")
	if server != "" {
		techs = append(techs, server)
	}
	
	// WAF & Security Layers
	if headers.Get("CF-RAY") != "" || headers.Get("cf-cache-status") != "" {
		techs = append(techs, "Cloudflare WAF/CDN")
	}
	if strings.Contains(strings.ToLower(headers.Get("X-Akamai-Transformed")), "true") {
		techs = append(techs, "Akamai CDN")
	}
	if headers.Get("X-Amz-Cf-Id") != "" {
		techs = append(techs, "AWS CloudFront")
	}
	if headers.Get("X-Azure-Ref") != "" {
		techs = append(techs, "Azure FrontDoor")
	}
	if strings.Contains(headers.Get("Via"), "google") {
		techs = append(techs, "Google Cloud Load Balancer")
	}

	// Security Headers (Tactical Intel)
	if headers.Get("X-Content-Type-Options") == "nosniff" {
		techs = append(techs, "Sec:HSTS")
	}
	if headers.Get("Content-Security-Policy") != "" {
		techs = append(techs, "Sec:CSP")
	}

	// App Frameworks & Servers
	if powered := headers.Get("X-Powered-By"); powered != "" {
		techs = append(techs, "PoweredBy:"+powered)
	}
	if generator := headers.Get("X-Generator"); generator != "" {
		techs = append(techs, "Generator:"+generator)
	}
	if aspVer := headers.Get("X-AspNet-Version"); aspVer != "" {
		techs = append(techs, "ASP.NET:"+aspVer)
	}
	if headers.Get("X-Drupal-Cache") != "" {
		techs = append(techs, "Drupal")
	}

	// 2. Body-Based Heuristics (Deep Scan)
	bodyLower := strings.ToLower(body)

	// CMS & E-commerce
	cmsMap := map[string][]string{
		"WordPress":   {"wp-content", "wp-includes", "wp-json"},
		"Joomla":      {"joomla", "/administrator/", "com_content"},
		"Drupal":      {"drupal", "sites/default"},
		"Magento":     {"magento", "mage-cache"},
		"Shopify":     {"shopify", "cdn.shopify.com"},
		"Squarespace": {"squarespace", "static1.squarespace.com"},
		"Wix":         {"wix.com", "wix-code-sdk"},
		"Webflow":     {"webflow", "w-nav"},
		"Ghost CMS":   {"ghost.org", "ghost-sdk"},
		"Bitrix":      {"bitrix", "/bitrix/"},
		"PrestaShop":  {"prestashop"},
		"OpenCart":    {"opencart"},
	}

	for tech, sigs := range cmsMap {
		for _, sig := range sigs {
			if strings.Contains(bodyLower, sig) {
				techs = append(techs, tech)
				break
			}
		}
	}

	// Frameworks & JS Libraries
	frameworkMap := map[string][]string{
		"Laravel":     {"laravel", "XSRF-TOKEN"},
		"Django":      {"django", "csrfmiddlewaretoken"},
		"React":       {"react", "react-dom", "data-reactid"},
		"Vue.js":      {"vue.js", "vuejs", "__vue__"},
		"Angular":     {"angular", "ng-app", "ng-controller"},
		"Next.js":     {"_next/static", "__NEXT_DATA__"},
		"Nuxt.js":     {"__NUXT__"},
		"Gatsby":      {"GatsbyJS"},
		"jQuery":      {"jquery"},
		"Bootstrap":   {"bootstrap"},
		"Tailwind":    {"tailwind"},
		"Webpack":     {"webpack"},
		"Svelte":      {"svelte-"},
	}

	for tech, sigs := range frameworkMap {
		for _, sig := range sigs {
			if strings.Contains(bodyLower, sig) {
				techs = append(techs, tech)
				break
			}
		}
	}

	// Analytics & Tracking
	trackingMap := map[string][]string{
		"Google Analytics":    {"google-analytics.com", "googletagmanager.com"},
		"Facebook Pixel":      {"connect.facebook.net/en_US/fbevents.js"},
		"Hotjar":              {"hotjar.com"},
		"New Relic":           {"newrelic.com", "NREUM"},
		"Sentry":              {"sentry.io"},
		"Datadog":             {"datadoghq.com"},
		"Segment":             {"segment.com"},
		"Mixpanel":            {"mixpanel.com"},
		"Intercom":            {"intercom.io", "intercom.help"},
		"HubSpot":             {"hubspot.com"},
		"Zendesk":             {"zendesk.com", "zdassets.com"},
		"Salesforce":          {"salesforce.com"},
	}

	for tech, sigs := range trackingMap {
		for _, sig := range sigs {
			if strings.Contains(bodyLower, sig) {
				techs = append(techs, tech)
				break
			}
		}
	}

	// Infrastructure & Cloud
	infraMap := map[string][]string{
		"Nginx":      {"nginx"},
		"Apache":     {"apache"},
		"Heroku":     {"heroku"},
		"Netlify":    {"netlify"},
		"Vercel":     {"vercel"},
		"Firebase":   {"firebaseapp.com", "firebase"},
		"Okta":       {"okta.com"},
		"Auth0":      {"auth0.com"},
		"Microsoft":  {"microsoft", "iis"},
		"OpenShift":  {"openshift"},
		"Kubernetes": {"k8s"},
	}

	for tech, sigs := range infraMap {
		for _, sig := range sigs {
			if strings.Contains(bodyLower, sig) {
				techs = append(techs, tech)
				break
			}
		}
	}

	return unique(techs)
}
