package main

import (
	"regexp"
	"strings"
)

type DetectedTech struct {
	Name       string  `json:"name"`
	Version    string  `json:"version,omitempty"`
	Category   string  `json:"category"`
	Confidence int     `json:"confidence"`
	Evidence   string  `json:"evidence,omitempty"`
}

type TechReport struct {
	Frontend        string         `json:"frontend"`
	Backend         string         `json:"backend"`
	WebServer       string         `json:"web_server"`
	ReverseProxy    string         `json:"reverse_proxy"`
	CMS             string         `json:"cms"`
	JSLibs          []DetectedTech `json:"js_libs"`
	CSSFrameworks   []DetectedTech `json:"css_frameworks"`
	Analytics       []DetectedTech `json:"analytics"`
	BuildTools      []DetectedTech `json:"build_tools"`
	PaymentGatways  []DetectedTech `json:"payment_gateways"`
	ChatWidgets     []DetectedTech `json:"chat_widgets"`
	TagManager      string         `json:"tag_manager"`
	CDN             string         `json:"cdn"`
	WebSockets      bool           `json:"web_sockets"`
	Ecommerce       string         `json:"ecommerce"`
	SSG             string         `json:"ssg"`
	CachePlugin     string         `json:"cache_plugin"`
	Database        string         `json:"database"`
	OS              string         `json:"os"`
	ProgrammingLang string         `json:"programming_lang"`
}

var (
	metaGenerator = regexp.MustCompile(`<meta\s+[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']`)
	metaAuthor    = regexp.MustCompile(`<meta\s+[^>]*name=["']author["'][^>]*content=["']([^"']+)["']`)
	scriptSrc     = regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	linkHref      = regexp.MustCompile(`<link[^>]+href=["']([^"']+)["']`)
	versionRegex  = regexp.MustCompile(`([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
)

func PerformTechDetection(body string, headers map[string]string) *TechReport {
	rep := &TechReport{}
	bodyLower := strings.ToLower(body)

	// Web Server from headers
	if srv, ok := headers["Server"]; ok {
		rep.WebServer = srv
	}

	// Reverse proxy detection
	if _, ok := headers["X-Varnish"]; ok {
		rep.ReverseProxy = "Varnish"
	}
	if via, ok := headers["Via"]; ok {
		v := strings.ToLower(via)
		switch {
		case strings.Contains(v, "varnish"):
			rep.ReverseProxy = "Varnish"
		case strings.Contains(v, "haproxy"):
			rep.ReverseProxy = "HAProxy"
		case strings.Contains(v, "nginx"):
			rep.ReverseProxy = "Nginx"
		case strings.Contains(v, "envoy"):
			rep.ReverseProxy = "Envoy"
		case strings.Contains(v, "traefik"):
			rep.ReverseProxy = "Traefik"
		case strings.Contains(v, "istio"):
			rep.ReverseProxy = "Istio"
		case strings.Contains(v, "kong"):
			rep.ReverseProxy = "Kong"
		}
	}
	if _, ok := headers["X-Served-By"]; ok {
		if rep.ReverseProxy == "" {
			rep.ReverseProxy = "Reverse Proxy"
		}
	}

	// Parse meta generator tag for CMS/framework version
	if m := metaGenerator.FindStringSubmatch(body); len(m) > 1 {
		gen := m[1]
		genLower := strings.ToLower(gen)
		switch {
		case strings.Contains(genLower, "wordpress"):
			rep.CMS = gen
		case strings.Contains(genLower, "drupal"):
			rep.CMS = gen
		case strings.Contains(genLower, "joomla"):
			rep.CMS = gen
		case strings.Contains(genLower, "jekyll"):
			rep.SSG = "Jekyll"
		case strings.Contains(genLower, "hugo"):
			rep.SSG = "Hugo"
		case strings.Contains(genLower, "gatsby"):
			rep.Frontend = "Gatsby"
		case strings.Contains(genLower, "next"):
			rep.Frontend = "Next.js"
		case strings.Contains(genLower, "vue"):
			rep.Frontend = "Vue.js"
		case strings.Contains(genLower, "angular"):
			rep.Frontend = "Angular"
		case strings.Contains(genLower, "laravel"):
			rep.Backend = "Laravel"
		case strings.Contains(genLower, "django"):
			rep.Backend = "Django"
		case strings.Contains(genLower, "rails"):
			rep.Backend = "Ruby on Rails"
		case strings.Contains(genLower, "asp.net"):
			rep.Backend = "ASP.NET"
		case strings.Contains(genLower, "shopify"):
			rep.Ecommerce = "Shopify"
		case strings.Contains(genLower, "squarespace"):
			rep.CMS = "Squarespace"
		case strings.Contains(genLower, "wix"):
			rep.CMS = "Wix"
		case strings.Contains(genLower, "weebly"):
			rep.CMS = "Weebly"
		case strings.Contains(genLower, "blogger"):
			rep.CMS = "Blogger"
		case strings.Contains(genLower, "tumblr"):
			rep.CMS = "Tumblr"
		case strings.Contains(genLower, "ghost"):
			rep.CMS = "Ghost"
		}
	}

	// Frontend detection (more comprehensive)
	frontendIndicators := []struct {
		key   string
		name  string
		prio  int
	}{
		{"react", "React", 1},
		{"reactdom", "React", 1},
		{"react.", "React", 1},
		{"create-react-app", "React", 1},
		{"_next/static", "Next.js", 2},
		{"next/", "Next.js", 2},
		{"nextjs", "Next.js", 2},
		{"nuxt", "Nuxt.js", 2},
		{"gatsby", "Gatsby", 2},
		{"vue", "Vue.js", 2},
		{"vue.js", "Vue.js", 2},
		{"vue-router", "Vue.js", 2},
		{"angular", "Angular", 3},
		{"ng-", "Angular", 3},
		{"ngversion", "Angular", 3},
		{"svelte", "Svelte", 3},
		{"solid-js", "Solid.js", 3},
		{"alpinejs", "Alpine.js", 3},
		{"stimulus", "Stimulus", 3},
		{"htmx", "htmx", 3},
		{"ember", "Ember.js", 3},
		{"backbone", "Backbone.js", 3},
		{"preact", "Preact", 3},
		{"lit-element", "Lit", 3},
	}
	if rep.Frontend == "" {
		bestPrio := 999
		for _, ind := range frontendIndicators {
			if strings.Contains(bodyLower, ind.key) && ind.prio < bestPrio {
				rep.Frontend = ind.name
				bestPrio = ind.prio
			}
		}
	}
	if rep.Frontend == "" {
		if strings.Contains(bodyLower, "spa") || strings.Contains(bodyLower, "single-page") {
			rep.Frontend = "Modern SPA (static)"
		} else {
			rep.Frontend = "Traditional/MVC SSR"
		}
	}

	// Backend detection (more comprehensive)
	backendHeaders := []struct {
		header string
		name   string
	}{
		{"X-Powered-By", ""},
		{"X-Runtime", "Ruby/Rails"},
		{"X-AspNet-Version", "ASP.NET"},
		{"X-AspNetMvc-Version", "ASP.NET MVC"},
		{"X-Drupal-Cache", "Drupal/PHP"},
		{"X-Drupal-Dynamic-Cache", "Drupal/PHP"},
		{"X-Generator", ""},
		{"X-Version", ""},
	}
	for _, bh := range backendHeaders {
		if v, ok := headers[bh.header]; ok {
			if bh.name != "" {
				rep.Backend = bh.name
			} else if v != "" {
				rep.Backend = v
			}
			break
		}
	}
	if rep.Backend == "" {
		backendIndicators := []struct {
			key  string
			name string
		}{
			{"laravel", "Laravel/PHP"},
			{"csrf-token", "Laravel/PHP"},
			{"django", "Django/Python"},
			{"csrftoken", "Django/Python"},
			{"express", "Node.js/Express"},
			{"connect.sid", "Node.js/Express"},
			{"spring", "Spring/Java"},
			{"java", "Spring/Java"},
			{"asp.net", "ASP.NET"},
			{"__viewstate", "ASP.NET"},
			{"__eventvalidation", "ASP.NET"},
			{"symfony", "Symfony/PHP"},
			{"codeigniter", "CodeIgniter/PHP"},
			{"cakephp", "CakePHP"},
			{"yii", "Yii/PHP"},
			{"flask", "Flask/Python"},
			{"fastapi", "FastAPI/Python"},
			{"gin", "Gin/Go"},
			{"fiber", "Fiber/Go"},
			{"echo", "Echo/Go"},
			{"rails", "Ruby on Rails"},
			{"rack", "Ruby/Rack"},
			{"phoenix", "Phoenix/Elixir"},
		}
		for _, bi := range backendIndicators {
			if strings.Contains(bodyLower, bi.key) {
				rep.Backend = bi.name
				break
			}
		}
	}
	if rep.Backend == "" {
		rep.Backend = "Custom/Inferred"
	}

	// CMS Detection (enhanced)
	cmsIndicators := []struct {
		key  string
		name string
	}{
		{"wp-content", "WordPress"},
		{"wp-json", "WordPress"},
		{"wordpress", "WordPress"},
		{"drupal", "Drupal"},
		{"drupal.js", "Drupal"},
		{"/sites/default/", "Drupal"},
		{"joomla", "Joomla"},
		{"/components/", "Joomla"},
		{"/modules/", "Joomla"},
		{"squarespace", "Squarespace"},
		{"static.squarespace", "Squarespace"},
		{"wix", "Wix"},
		{"wixstatic", "Wix"},
		{"shopify", "Shopify"},
		{"myshopify", "Shopify"},
		{"blogger", "Blogger"},
		{".blogspot.com", "Blogger"},
		{"tumblr", "Tumblr"},
		{"ghost", "Ghost"},
		{"hubspot", "HubSpot"},
		{"webflow", "Webflow"},
		{"strikingly", "Strikingly"},
		{"weebly", "Weebly"},
		{" Sitefinity ", "Sitefinity"},
		{"umbraco", "Umbraco"},
		{"typo3", "TYPO3"},
		{"magento", "Magento"},
		{"woocommerce", "WooCommerce"},
		{"prestashop", "PrestaShop"},
		{"opencart", "OpenCart"},
	}
	if rep.CMS == "" {
		for _, ci := range cmsIndicators {
			if strings.Contains(bodyLower, ci.key) {
				rep.CMS = ci.name
				break
			}
		}
	}
	if rep.CMS == "" {
		rep.CMS = "Custom/Proprietary"
	}

	// Ecommerce detection
	ecomIndicators := []string{"cart", "checkout", "add-to-cart", "addtocart", "shopping-cart", "view-cart", "product-price", "woocommerce", "magento", "shopify"}
	for _, k := range ecomIndicators {
		if strings.Contains(bodyLower, k) {
			if rep.Ecommerce == "" {
				rep.Ecommerce = "E-commerce Detected"
			}
			break
		}
	}

	// SSG detection
	ssgIndicators := []struct {
		key  string
		name string
	}{
		{"jekyll", "Jekyll"},
		{"hugo", "Hugo"},
		{"gatsby", "Gatsby"},
		{"next", "Next.js"},
		{"nuxt", "Nuxt.js"},
		{"eleventy", "Eleventy"},
		{"11ty", "Eleventy"},
		{"hexo", "Hexo"},
		{"vuepress", "VuePress"},
		{"docusaurus", "Docusaurus"},
		{"mkdocs", "MkDocs"},
		{"readthedocs", "Read the Docs"},
	}
	if rep.SSG == "" {
		for _, si := range ssgIndicators {
			if strings.Contains(bodyLower, si.key) {
				rep.SSG = si.name
				break
			}
		}
	}

	// Database detection
	dbIndicators := []struct {
		key  string
		name string
	}{
		{"mysql", "MySQL / MariaDB"},
		{"maria", "MySQL / MariaDB"},
		{"postgresql", "PostgreSQL"},
		{"postgres", "PostgreSQL"},
		{"mongodb", "MongoDB"},
		{"sqlite", "SQLite"},
		{"redis", "Redis"},
		{"memcached", "Memcached"},
		{"elasticsearch", "Elasticsearch"},
		{"cassandra", "Cassandra"},
		{"couchdb", "CouchDB"},
		{"firebase", "Firebase"},
		{"dynamodb", "DynamoDB"},
	}
	for _, di := range dbIndicators {
		if strings.Contains(bodyLower, di.key) {
			rep.Database = di.name
			break
		}
	}

	// OS detection from headers
	if srv, ok := headers["Server"]; ok {
		srvLower := strings.ToLower(srv)
		if strings.Contains(srvLower, "ubuntu") {
			rep.OS = "Ubuntu Linux"
		} else if strings.Contains(srvLower, "debian") {
			rep.OS = "Debian Linux"
		} else if strings.Contains(srvLower, "centos") {
			rep.OS = "CentOS Linux"
		} else if strings.Contains(srvLower, "red hat") || strings.Contains(srvLower, "rhel") {
			rep.OS = "Red Hat Enterprise Linux"
		} else if strings.Contains(srvLower, "alpine") {
			rep.OS = "Alpine Linux"
		} else if strings.Contains(srvLower, "freebsd") {
			rep.OS = "FreeBSD"
		} else if strings.Contains(srvLower, "openbsd") {
			rep.OS = "OpenBSD"
		} else if strings.Contains(srvLower, "netbsd") {
			rep.OS = "NetBSD"
		} else if strings.Contains(srvLower, "windows") || strings.Contains(srvLower, "win32") || strings.Contains(srvLower, "iis") {
			rep.OS = "Windows Server"
		}
	}
	if rep.OS == "" && rep.WebServer != "" {
		ws := strings.ToLower(rep.WebServer)
		if strings.Contains(ws, "iis") {
			rep.OS = "Windows Server"
		} else if strings.Contains(ws, "nginx") || strings.Contains(ws, "apache") || strings.Contains(ws, "lighttpd") || strings.Contains(ws, "caddy") || strings.Contains(ws, "openresty") {
			rep.OS = "Linux/Unix"
		}
	}

	// Programming language detection
	langIndicators := []struct {
		key  string
		name string
	}{
		{".php", "PHP"},
		{".asp", "ASP"},
		{".aspx", "ASP.NET"},
		{".jsp", "Java/JSP"},
		{".py", "Python"},
		{".rb", "Ruby"},
		{".go", "Go"},
		{".java", "Java"},
		{".node", "Node.js"},
		{"node_modules", "Node.js"},
		{".cgi", "Perl/CGI"},
		{".pl", "Perl"},
	}
	for _, li := range langIndicators {
		if strings.Contains(bodyLower, li.key) {
			rep.ProgrammingLang = li.name
			break
		}
	}

	// JavaScript Libraries (extended)
	jsLibs := map[string]string{
		"jquery":        "jQuery",
		"lodash":        "Lodash",
		"axios":         "Axios",
		"moment":        "Moment.js",
		"dayjs":         "Day.js",
		"underscore":    "Underscore.js",
		"chart.js":      "Chart.js",
		"d3.js":         "D3.js",
		"three.js":      "Three.js",
		"swiper":        "Swiper",
		"select2":       "Select2",
		"datatables":    "DataTables",
		"tinymce":       "TinyMCE",
		"ckeditor":      "CKEditor",
		"fullcalendar":  "FullCalendar",
		"flatpickr":     "Flatpickr",
		"choices.js":    "Choices.js",
		"dropzone":      "Dropzone",
		"quill":         "Quill",
		"summernote":    "Summernote",
		"highlight.js":  "Highlight.js",
		"prism.js":      "Prism.js",
		"masonry":       "Masonry",
		"isotope":       "Isotope",
		"fancybox":      "Fancybox",
		"lightbox":      "Lightbox",
		"swal":          "SweetAlert2",
		"izitoast":      "IziToast",
		"toastr":        "Toastr",
		"owl.carousel":  "Owl Carousel",
		"slick":         "Slick Carousel",
		"aos":           "AOS (Animate on Scroll)",
		"typed.js":      "Typed.js",
		"countup":       "CountUp.js",
		"waypoints":     "Waypoints.js",
		"gsap":          "GSAP",
		"animejs":       "Anime.js",
		"mo-js":         "Mo.js",
		"particles.js":  "Particles.js",
		"leaflet":       "Leaflet",
		"mapbox":        "Mapbox GL JS",
		"google.maps":   "Google Maps API",
		"amcharts":      "amCharts",
		"highcharts":    "Highcharts",
		"echarts":       "ECharts",
		"recharts":      "Recharts",
	}
	for key, name := range jsLibs {
		if strings.Contains(bodyLower, key) {
			rep.JSLibs = append(rep.JSLibs, DetectedTech{
				Name: name, Category: "JavaScript Library", Confidence: 70,
			})
		}
	}

	// CSS Frameworks (extended)
	if strings.Contains(bodyLower, "bootstrap") {
		rep.CSSFrameworks = append(rep.CSSFrameworks, DetectedTech{Name: "Bootstrap", Category: "CSS Framework", Confidence: 80})
	}
	if strings.Contains(bodyLower, "tailwind") || strings.Contains(bodyLower, "tw-") {
		rep.CSSFrameworks = append(rep.CSSFrameworks, DetectedTech{Name: "Tailwind CSS", Category: "CSS Framework", Confidence: 75})
	}
	if strings.Contains(bodyLower, "foundation") && strings.Contains(bodyLower, "foundation.min.css") {
		rep.CSSFrameworks = append(rep.CSSFrameworks, DetectedTech{Name: "Foundation", Category: "CSS Framework", Confidence: 70})
	}
	if strings.Contains(bodyLower, "bulma") {
		rep.CSSFrameworks = append(rep.CSSFrameworks, DetectedTech{Name: "Bulma", Category: "CSS Framework", Confidence: 70})
	}
	if strings.Contains(bodyLower, "materialize") {
		rep.CSSFrameworks = append(rep.CSSFrameworks, DetectedTech{Name: "Materialize CSS", Category: "CSS Framework", Confidence: 70})
	}
	if strings.Contains(bodyLower, "mui") || strings.Contains(bodyLower, "material-ui") {
		rep.CSSFrameworks = append(rep.CSSFrameworks, DetectedTech{Name: "Material UI", Category: "CSS Framework", Confidence: 75})
	}
	if strings.Contains(bodyLower, "chakra") {
		rep.CSSFrameworks = append(rep.CSSFrameworks, DetectedTech{Name: "Chakra UI", Category: "CSS Framework", Confidence: 70})
	}
	if strings.Contains(bodyLower, "ant-design") || strings.Contains(bodyLower, "antd") {
		rep.CSSFrameworks = append(rep.CSSFrameworks, DetectedTech{Name: "Ant Design", Category: "CSS Framework", Confidence: 75})
	}
	if strings.Contains(bodyLower, "semantic-ui") || strings.Contains(bodyLower, "semantic") {
		rep.CSSFrameworks = append(rep.CSSFrameworks, DetectedTech{Name: "Semantic UI", Category: "CSS Framework", Confidence: 70})
	}
	if strings.Contains(bodyLower, "purecss") || strings.Contains(bodyLower, "pure.css") {
		rep.CSSFrameworks = append(rep.CSSFrameworks, DetectedTech{Name: "Pure.css", Category: "CSS Framework", Confidence: 65})
	}

	// Analytics (extended)
	analyticsMap := []struct {
		key  string
		name string
	}{
		{"google-analytics", "Google Analytics"},
		{"gtag", "Google Analytics 4"},
		{"ga('", "Google Analytics"},
		{"ga.create", "Google Analytics"},
		{"facebook.com/tr", "Facebook Pixel"},
		{"fbq(", "Facebook Pixel"},
		{"hotjar", "Hotjar"},
		{"mixpanel", "Mixpanel"},
		{"amplitude", "Amplitude"},
		{"segment", "Segment"},
		{"heap", "Heap Analytics"},
		{"fullstory", "FullStory"},
		{"crazyegg", "Crazy Egg"},
		{"clarity", "Microsoft Clarity"},
		{"mouseflow", "Mouseflow"},
		{"clicky", "Clicky"},
		{"matomo", "Matomo"},
		{"piwik", "Piwik"},
		{"plausible", "Plausible"},
		{"fathom", "Fathom Analytics"},
		{"simpleanalytics", "Simple Analytics"},
		{"hubspot", "HubSpot Analytics"},
		{"linkedin-insight", "LinkedIn Insight Tag"},
		{"twitter-pixel", "Twitter Pixel"},
		{"pinterest", "Pinterest Tag"},
		{"tiktok-pixel", "TikTok Pixel"},
		{"snapchat", "Snapchat Pixel"},
		{"reddit", "Reddit Pixel"},
		{"quora", "Quora Pixel"},
		{"bing", "Bing Ads"},
		{"adwords", "Google Ads"},
	}
	for _, am := range analyticsMap {
		if strings.Contains(bodyLower, am.key) {
			rep.Analytics = append(rep.Analytics, DetectedTech{Name: am.name, Category: "Analytics", Confidence: 80})
		}
	}

	// Tag Manager
	if strings.Contains(bodyLower, "gtm-") || strings.Contains(bodyLower, "googletagmanager") {
		rep.TagManager = "Google Tag Manager"
	}
	if strings.Contains(bodyLower, "tagmanager") || strings.Contains(bodyLower, "tealium") {
		if rep.TagManager == "" {
			rep.TagManager = "Tag Manager Detected"
		}
	}

	// Payment Gateways (extended)
	paymentMap := []struct {
		key  string
		name string
	}{
		{"stripe", "Stripe"},
		{"pk_", "Stripe"},
		{"paypal", "PayPal"},
		{"paypal.com", "PayPal"},
		{"braintree", "Braintree"},
		{"square", "Square"},
		{"authorize.net", "Authorize.net"},
		{"2checkout", "2Checkout"},
		{"adyen", "Adyen"},
		{"klarna", "Klarna"},
		{"afterpay", "Afterpay"},
		{"sezzle", "Sezzle"},
		{"shopify-payments", "Shopify Payments"},
		{"woocommerce", "WooCommerce Payments"},
		{"midtrans", "Midtrans"},
		{"xendit", "Xendit"},
		{"doku", "DOKU"},
	}
	for _, pm := range paymentMap {
		if strings.Contains(bodyLower, pm.key) {
			rep.PaymentGatways = append(rep.PaymentGatways, DetectedTech{Name: pm.name, Category: "Payment", Confidence: 75})
		}
	}

	// Chat Widgets (extended)
	chatMap := []struct {
		key  string
		name string
	}{
		{"intercom", "Intercom"},
		{"drift", "Drift"},
		{"tawk.to", "Tawk.to"},
		{"tawkto", "Tawk.to"},
		{"livechat", "LiveChat"},
		{"zendesk", "Zendesk Chat"},
		{"zopim", "Zendesk Chat"},
		{"crisp", "Crisp Chat"},
		{"freshchat", "Freshchat"},
		{"freshdesk", "Freshdesk"},
		{"olark", "Olark"},
		{"liveperson", "LivePerson"},
		{"tidio", "Tidio"},
		{"chatbot", "Chatbot.com"},
		{"manychat", "ManyChat"},
		{"chatra", "Chatra"},
		{"smartsupp", "Smartsupp"},
		{"messenger", "Facebook Messenger"},
		{"whatsapp", "WhatsApp Chat"},
		{"telegram", "Telegram Chat"},
		{"line.me", "LINE Chat"},
	}
	for _, cm := range chatMap {
		if strings.Contains(bodyLower, cm.key) {
			rep.ChatWidgets = append(rep.ChatWidgets, DetectedTech{Name: cm.name, Category: "Chat", Confidence: 75})
		}
	}

	// WebSocket detection
	if strings.Contains(bodyLower, "websocket") || strings.Contains(bodyLower, "wss://") || strings.Contains(bodyLower, "socket.io") {
		rep.WebSockets = true
	}

	// Cache plugin detection
	cacheIndicators := []struct {
		key  string
		name string
	}{
		{"wp-super-cache", "WP Super Cache"},
		{"w3-total-cache", "W3 Total Cache"},
		{"wp-rocket", "WP Rocket"},
		{"litespeed", "LiteSpeed Cache"},
		{"varnish", "Varnish Cache"},
		{"redis-cache", "Redis Cache"},
		{"cloudflare", "Cloudflare"},
		{"fastly", "Fastly"},
	}
	for _, ci := range cacheIndicators {
		if strings.Contains(bodyLower, ci.key) {
			rep.CachePlugin = ci.name
			break
		}
	}

	// Build Tools (extended)
	if strings.Contains(bodyLower, "webpack") || strings.Contains(bodyLower, "/__webpack_") {
		rep.BuildTools = append(rep.BuildTools, DetectedTech{Name: "Webpack", Category: "Build Tool", Confidence: 70})
	}
	if strings.Contains(bodyLower, "vite") || strings.Contains(bodyLower, "vite.") {
		rep.BuildTools = append(rep.BuildTools, DetectedTech{Name: "Vite", Category: "Build Tool", Confidence: 70})
	}
	if strings.Contains(bodyLower, "rollup") {
		rep.BuildTools = append(rep.BuildTools, DetectedTech{Name: "Rollup", Category: "Build Tool", Confidence: 65})
	}
	if strings.Contains(bodyLower, "parcel") {
		rep.BuildTools = append(rep.BuildTools, DetectedTech{Name: "Parcel", Category: "Build Tool", Confidence: 65})
	}
	if strings.Contains(bodyLower, "esbuild") {
		rep.BuildTools = append(rep.BuildTools, DetectedTech{Name: "ESBuild", Category: "Build Tool", Confidence: 65})
	}
	if strings.Contains(bodyLower, "turbo") || strings.Contains(bodyLower, "turbopack") {
		rep.BuildTools = append(rep.BuildTools, DetectedTech{Name: "Turbopack", Category: "Build Tool", Confidence: 60})
	}
	if strings.Contains(bodyLower, "gulp") {
		rep.BuildTools = append(rep.BuildTools, DetectedTech{Name: "Gulp", Category: "Build Tool", Confidence: 65})
	}
	if strings.Contains(bodyLower, "grunt") {
		rep.BuildTools = append(rep.BuildTools, DetectedTech{Name: "Grunt", Category: "Build Tool", Confidence: 65})
	}

	// CDN from headers
	if _, ok := headers["CF-Ray"]; ok {
		rep.CDN = "Cloudflare"
	} else if _, ok := headers["X-Cache"]; ok && strings.Contains(strings.ToLower(headers["X-Cache"]), "cloudfront") {
		rep.CDN = "AWS CloudFront"
	} else if _, ok := headers["Akamai-Origin-Hop"]; ok {
		rep.CDN = "Akamai"
	} else if _, ok := headers["X-Sucuri-ID"]; ok {
		rep.CDN = "Sucuri"
	} else if _, ok := headers["Fastly-Debug"]; ok || strings.Contains(strings.ToLower(headers["X-Cache"]), "fastly") {
		rep.CDN = "Fastly"
	} else if _, ok := headers["X-CDN"]; ok {
		rep.CDN = headers["X-CDN"]
	}

	return rep
}
