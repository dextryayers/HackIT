package main

import (
	"net/http"
	"strings"
)

func detectTech(headers http.Header, body string) []string {
	var techs []string
	bodyLower := strings.ToLower(body)

	// 1. Header-Based Server Detection
	server := headers.Get("Server")
	if server != "" {
		serverLower := strings.ToLower(server)
		switch {
		case strings.Contains(serverLower, "cloudflare"):
			techs = append(techs, "Cloudflare")
		case strings.Contains(serverLower, "nginx"):
			techs = append(techs, "Nginx")
		case strings.Contains(serverLower, "apache"):
			techs = append(techs, "Apache")
		case strings.Contains(serverLower, "iis") || strings.Contains(serverLower, "microsoft-iis"):
			techs = append(techs, "IIS")
		case strings.Contains(serverLower, "openresty"):
			techs = append(techs, "OpenResty")
		case strings.Contains(serverLower, "caddy"):
			techs = append(techs, "Caddy")
		case strings.Contains(serverLower, "litespeed"):
			techs = append(techs, "LiteSpeed")
		case strings.Contains(serverLower, "amazons3") || strings.Contains(serverLower, "amazon s3"):
			techs = append(techs, "AWS S3")
		case strings.Contains(serverLower, "gfe") || strings.Contains(serverLower, "google frontend"):
			techs = append(techs, "Google Frontend")
		case strings.Contains(serverLower, "cloudfront"):
			techs = append(techs, "CloudFront")
		case strings.Contains(serverLower, "fastly"):
			techs = append(techs, "Fastly")
		case strings.Contains(serverLower, "envoy"):
			techs = append(techs, "Envoy")
		default:
			techs = append(techs, server)
		}
	}

	// 2. WAF Detection
	wafHeaders := map[string]string{
		"cf-ray": "Cloudflare", "cf-cache-status": "Cloudflare",
		"x-akamai-transformed": "Akamai",
		"x-amz-cf-id": "AWS CloudFront",
		"x-azure-ref": "Azure FrontDoor",
		"x-sucuri-id": "Sucuri", "x-sucuri-cache": "Sucuri",
		"incap-sess": "Imperva", "visid_incap": "Imperva",
		"x-iinfo": "F5 BIG-IP", "x-edge-ip": "F5 BIG-IP",
		"x-dotdefense": "DotDefender",
		"x-wep-waf": "AWS WAF",
	}
	for h, w := range wafHeaders {
		if headers.Get(h) != "" {
			techs = append(techs, "WAF:"+w)
		}
	}

	// 3. Powered-By / Generator Headers
	if p := headers.Get("X-Powered-By"); p != "" {
		techs = append(techs, "PoweredBy:"+p)
	}
	if g := headers.Get("X-Generator"); g != "" {
		techs = append(techs, "Generator:"+g)
	}
	if a := headers.Get("X-AspNet-Version"); a != "" {
		techs = append(techs, "ASP.NET:"+a)
	}
	if headers.Get("X-Drupal-Cache") != "" {
		techs = append(techs, "Drupal")
	}
	if headers.Get("X-Drupal-Dynamic-Cache") != "" {
		techs = append(techs, "Drupal")
	}
	if r := headers.Get("X-Runtime"); r != "" {
		techs = append(techs, "Ruby/Rails:"+r)
	}
	if p := headers.Get("X-Pingback"); p != "" {
		techs = append(techs, "WordPress (Pingback)")
	}

	// 4. Language / Framework Cookies & Headers
	for _, c := range strings.Split(headers.Get("Set-Cookie"), "\n") {
		cl := strings.ToLower(c)
		switch {
		case strings.Contains(cl, "laravel_session"):
			techs = append(techs, "Laravel")
		case strings.Contains(cl, "symfony"):
			techs = append(techs, "Symfony")
		case strings.Contains(cl, "django"):
			techs = append(techs, "Django")
		case strings.Contains(cl, "rails") || strings.Contains(cl, "_session"):
			techs = append(techs, "Ruby on Rails")
		case strings.Contains(cl, "wordpress_") || strings.Contains(cl, "wp-"):
			techs = append(techs, "WordPress")
		case strings.Contains(cl, "PHPSESSID") || strings.Contains(cl, "php"):
			techs = append(techs, "PHP")
		case strings.Contains(cl, "JSESSIONID"):
			techs = append(techs, "Java/JSP")
		case strings.Contains(cl, "ASP.NET_SessionId") || strings.Contains(cl, "aspsessionid"):
			techs = append(techs, "ASP.NET")
		case strings.Contains(cl, "expires") && strings.Contains(cl, "node"):
			techs = append(techs, "Node.js")
		}
	}

	// 5. Body-Based CMS Detection
	cmsSignatures := map[string][]string{
		"WordPress":  {"wp-content", "wp-includes", "wp-json", "wordpress", "wp-admin"},
		"Joomla":     {"joomla", "/administrator/", "com_content", "com_k2"},
		"Drupal":     {"drupal", "sites/default", "drupal.js"},
		"Magento":    {"magento", "mage-cache", "mage/", "varien"},
		"Shopify":    {"shopify", "cdn.shopify.com", "myshopify.com"},
		"Squarespace": {"squarespace", "static1.squarespace.com", "squarespace.com"},
		"Wix":        {"wix.com", "wix-static", "wix-bridge"},
		"Webflow":    {"webflow", "w-nav", "w-editor"},
		"Ghost CMS":  {"ghost.org", "ghost-sdk", "ghost"},
		"Bitrix":     {"bitrix", "/bitrix/", "bx"},
		"PrestaShop": {"prestashop", "ps_"},
		"OpenCart":   {"opencart", "route=common"},
		"TYPO3":      {"typo3", "typo3temp"},
		"Concrete5":  {"concrete5", "concrete/"},
		"OctoberCMS": {"octobercms", "october"},
		"CraftCMS":   {"craftcms", "craft/config"},
	}
	for cms, sigs := range cmsSignatures {
		for _, s := range sigs {
			if strings.Contains(bodyLower, s) {
				techs = append(techs, cms)
				break
			}
		}
	}

	// 6. JavaScript Frameworks
	jsSignatures := map[string][]string{
		"React":     {"react", "react-dom", "data-reactid", "reactroot", "__NEXT_DATA__"},
		"Vue.js":    {"vue.js", "vuejs", "__vue__", "vue-router", "v-cloak"},
		"Angular":   {"angular", "ng-app", "ng-controller", "ng-view", "angular.js"},
		"Next.js":   {"_next/static", "__NEXT_DATA__", "nextjs"},
		"Nuxt.js":   {"__NUXT__", "nuxt"},
		"Gatsby":    {"gatsby", "___gatsby"},
		"Svelte":    {"svelte-", "sveltekit"},
		"jQuery":    {"jquery", "jquery.js"},
		"Bootstrap": {"bootstrap", "bootstrap.", "bootstrapcdn"},
		"Tailwind":  {"tailwind", "tailwindcss"},
		"Webpack":   {"webpack", "__webpack_require__"},
		"Alpine.js": {"alpinejs", "x-data", "x-init"},
		"HTMX":      {"htmx", "hx-get", "hx-post", "hx-trigger"},
		"Stimulus":  {"stimulus", "data-controller"},
		"Turbolinks": {"turbolinks", "turbo-track"},
		"Ember.js":  {"ember.js", "emberjs"},
		"Backbone.js": {"backbone", "backbone.js"},
		"Socket.IO": {"socket.io", "socket-io"},
		"Chart.js":  {"chart.js", "chartjs"},
		"GSAP":      {"gsap", "greensock"},
		"Three.js":  {"three.js", "threejs"},
		"D3.js":     {"d3.js", "d3js"},
	}
	for js, sigs := range jsSignatures {
		for _, s := range sigs {
			if strings.Contains(bodyLower, s) {
				techs = append(techs, js)
				break
			}
		}
	}

	// 7. Analytics / Tracking
	analyticsSignatures := map[string][]string{
		"Google Analytics":    {"google-analytics.com/analytics.js", "googletagmanager.com/gtag/js", "ga(", "gtag("},
		"Google Tag Manager": {"googletagmanager.com/ns.html", "gtm.start"},
		"Facebook Pixel":     {"connect.facebook.net/en_US/fbevents.js", "fbq("},
		"Hotjar":             {"hotjar.com", "hj("},
		"New Relic":          {"newrelic.com", "NREUM"},
		"Sentry":             {"sentry.io", "sentry.min.js", "Sentry.init"},
		"Datadog":            {"datadoghq.com", "DATADOG"},
		"Segment":            {"segment.com/analytics.js", "analytics.load"},
		"Mixpanel":           {"mixpanel.com", "mixpanel.init"},
		"Intercom":           {"intercom.io", "intercom"},
		"HubSpot":            {"hubspot.com", "hs-analytics"},
		"Zendesk":            {"zendesk.com", "zdassets.com", "zopim"},
		"Salesforce":         {"salesforce.com", "sfdc"},
		"LinkedIn Insight":   {"linkedin.com/insight", "snap.licdn.com"},
		"Twitter Pixel":      {"static.ads-twitter.com", "twq("},
		"TikTok Pixel":       {"tiktok.com/pixel", "ttq("},
		"Clarity":            {"clarity.microsoft.com", "clarity"},
		"Amplitude":          {"amplitude.com", "amplitude"},
		"FullStory":          {"fullstory.com", "FS"},
		"Heap":               {"heapanalytics.com", "heap"},
	}
	for a, sigs := range analyticsSignatures {
		for _, s := range sigs {
			if strings.Contains(bodyLower, s) {
				techs = append(techs, a)
				break
			}
		}
	}

	// 8. Infrastructure / Cloud
	infraSignatures := map[string][]string{
		"Heroku":       {"heroku", "herokuapp"},
		"Netlify":      {"netlify", "netlify.app"},
		"Vercel":       {"vercel", "vercel.app", "_vercel"},
		"Firebase":     {"firebase", "firebaseapp"},
		"AWS":          {"amazonaws.com", "aws", "ec2"},
		"Azure":        {"azure", "azurewebsites", "windows.net"},
		"GCP":          {"googlecloud", "appspot.com", "gcp"},
		"DigitalOcean": {"digitalocean", "do-"},
		"Cloudflare":   {"cloudflare", "cdn-cgi"},
		"Okta":         {"okta.com", "okta"},
		"Auth0":        {"auth0.com", "auth0"},
		"GitHub Pages": {"github.io"},
		"GitLab Pages": {"gitlab.io"},
		"Kubernetes":   {"k8s", "kubernetes", "kube"},
		"Docker":       {"docker", "docker.com"},
	}
	for infra, sigs := range infraSignatures {
		for _, s := range sigs {
			if strings.Contains(bodyLower, s) || strings.Contains(strings.ToLower(server), s) {
				techs = append(techs, infra)
				break
			}
		}
	}

	return unique(techs)
}
