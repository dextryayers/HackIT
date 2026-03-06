package main

type Signature struct {
	Type    string `json:"type"` // meta, header, cookie, script, html, url, style
	Name    string `json:"name,omitempty"`
	Pattern string `json:"pattern"`
}

var Technologies = map[string][]Signature{
	"Nginx": {
		{Type: "header", Name: "Server", Pattern: `nginx/?([0-9.]*)?`},
	},
	"Apache": {
		{Type: "header", Name: "Server", Pattern: `Apache/?([0-9.]*)?`},
	},
	"IIS": {
		{Type: "header", Name: "Server", Pattern: `IIS/?([0-9.]*)?`},
	},
	"LiteSpeed": {
		{Type: "header", Name: "Server", Pattern: `LiteSpeed`},
	},
	"PHP": {
		{Type: "header", Name: "X-Powered-By", Pattern: `PHP/?([0-9.]*)?`},
		{Type: "cookie", Pattern: `PHPSESSID`},
	},
	"ASP.NET": {
		{Type: "header", Name: "X-AspNet-Version", Pattern: `.+`},
		{Type: "cookie", Pattern: `ASP.NET_SessionId`},
	},
	"Java": {
		{Type: "cookie", Pattern: `JSESSIONID`},
	},
	"Node.js": {
		{Type: "header", Name: "X-Powered-By", Pattern: `Express`},
	},
	"Python": {
		{Type: "header", Name: "Server", Pattern: `gunicorn`},
	},
	"WordPress": {
		{Type: "meta", Pattern: `name="generator" content="WordPress ?([0-9.]*)`},
		{Type: "url", Pattern: `wp-content/`},
		{Type: "url", Pattern: `wp-includes/`},
		{Type: "url", Pattern: `/wp-admin`},
	},
	"Joomla": {
		{Type: "meta", Pattern: `name="generator" content="Joomla!"`},
		{Type: "url", Pattern: `/administrator/`},
	},
	"Drupal": {
		{Type: "html", Pattern: `Drupal.settings`},
		{Type: "url", Pattern: `sites/default`},
	},
	"Magento": {
		{Type: "html", Pattern: `Mage.Cookies`},
		{Type: "url", Pattern: `index.php/admin`},
	},
	"Shopify": {
		{Type: "header", Name: "X-Shopify-Stage", Pattern: `.+`},
		{Type: "html", Pattern: `cdn.shopify.com`},
	},
	"Ghost": {
		{Type: "html", Pattern: `ghost-content`},
	},
	"Laravel": {
		{Type: "cookie", Pattern: `laravel_session`},
		{Type: "cookie", Pattern: `XSRF-TOKEN`},
	},
	"Django": {
		{Type: "cookie", Pattern: `csrftoken`},
	},
	"Google Web Server": {
		{Type: "header", Name: "Server", Pattern: `gws`},
	},
	"Spring Boot": {
		{Type: "header", Name: "X-Application-Context", Pattern: `.+`},
	},
	"Ruby on Rails": {
		{Type: "cookie", Pattern: `_rails_session`},
	},
	"Express": {
		{Type: "header", Name: "X-Powered-By", Pattern: `Express`},
	},
	"React": {
		{Type: "script", Pattern: `react\.production\.min\.js`},
		{Type: "html", Pattern: `data-reactroot`},
	},
	"Vue.js": {
		{Type: "script", Pattern: `vue\.js`},
		{Type: "html", Pattern: `__vue__`},
	},
	"Angular": {
		{Type: "script", Pattern: `angular\.js`},
		{Type: "html", Pattern: `ng-version`},
	},
	"Next.js": {
		{Type: "script", Pattern: `_next/static`},
		{Type: "html", Pattern: `__NEXT_DATA__`},
	},
	"Nuxt.js": {
		{Type: "html", Pattern: `__NUXT__`},
	},
	"MySQL": {
		{Type: "html", Pattern: `MySQL server version`},
	},
	"PostgreSQL": {
		{Type: "html", Pattern: `PostgreSQL`},
	},
	"MongoDB": {
		{Type: "html", Pattern: `MongoDB`},
	},
	"OAuth": {
		{Type: "url", Pattern: `/oauth`},
	},
	"SAML": {
		{Type: "html", Pattern: `SAMLResponse`},
	},
	"Keycloak": {
		{Type: "html", Pattern: `keycloak`},
	},
	"Cloudflare": {
		{Type: "header", Name: "CF-RAY", Pattern: `.+`},
		{Type: "header", Name: "Server", Pattern: `cloudflare`},
	},
	"AWS": {
		{Type: "header", Name: "X-Amz-Request-ID", Pattern: `.+`},
	},
	"GCP": {
		{Type: "header", Name: "X-Goog", Pattern: `.+`},
	},
	"Azure": {
		{Type: "header", Name: "X-Azure-Ref", Pattern: `.+`},
	},
	"Akamai": {
		{Type: "header", Name: "Akamai", Pattern: `.+`},
	},
	"Fastly": {
		{Type: "header", Name: "X-Served-By", Pattern: `cache-`},
	},
	"Cloudfront": {
		{Type: "header", Name: "X-Amz-Cf-ID", Pattern: `.+`},
	},
	"Grafana": {
		{Type: "html", Pattern: `grafanaBootData`},
	},
	"Prometheus": {
		{Type: "html", Pattern: `prometheus`},
	},
	"Jenkins": {
		{Type: "header", Name: "X-Jenkins", Pattern: `.+`},
	},
	"GitLab": {
		{Type: "html", Pattern: `gitlab`},
	},
	"Bitbucket": {
		{Type: "html", Pattern: `bitbucket`},
	},
	"Elasticsearch": {
		{Type: "header", Name: "Elasticsearch", Pattern: `.+`},
	},
	"Solr": {
		{Type: "header", Name: "Server", Pattern: `Apache Solr`},
	},
	"GSAP": {
		{Type: "script", Pattern: `gsap(?:\.min)?\.js`},
		{Type: "html", Pattern: `TweenMax|TweenLite|TimelineMax`},
	},
	"Astro": {
		{Type: "html", Pattern: `astro-island|astro-`},
	},
	"Svelte": {
		{Type: "html", Pattern: `svelte-`},
		{Type: "script", Pattern: `svelte`},
	},
	"jQuery": {
		{Type: "script", Pattern: `jquery(?:\.min)?\.js`},
		{Type: "html", Pattern: `jQuery`},
	},
	"Blogger": {
		{Type: "meta", Pattern: `name="generator" content="blogger"`},
		{Type: "html", Pattern: `blogger\.com`},
	},
	"Wix": {
		{Type: "meta", Pattern: `name="generator" content="Wix\.com Website Builder"`},
		{Type: "html", Pattern: `static\.wixstatic\.com`},
	},
	"Squarespace": {
		{Type: "header", Name: "X-Served-By", Pattern: `Squarespace`},
		{Type: "html", Pattern: `static1\.squarespace\.com`},
	},
	"TYPO3": {
		{Type: "meta", Pattern: `name="generator" content="TYPO3 CMS"`},
		{Type: "url", Pattern: `typo3temp/`},
	},
	"PrestaShop": {
		{Type: "meta", Pattern: `name="generator" content="PrestaShop"`},
		{Type: "html", Pattern: `prestashop`},
	},
	"Tailwind CSS": {
		{Type: "html", Pattern: `tailwind`},
	},
	"Bootstrap": {
		{Type: "html", Pattern: `bootstrap(?:\.min)?\.css`},
		{Type: "script", Pattern: `bootstrap(?:\.min)?\.js`},
	},
	"Alpine.js": {
		{Type: "html", Pattern: `x-data=`},
		{Type: "script", Pattern: `alpine(?:\.min)?\.js`},
	},
	"SolidJS": {
		{Type: "html", Pattern: `solid-js`},
	},
	"Caddy": {
		{Type: "header", Name: "Server", Pattern: `Caddy`},
	},
	"OpenResty": {
		{Type: "header", Name: "Server", Pattern: `openresty`},
	},
	"Varnish": {
		{Type: "header", Name: "X-Varnish", Pattern: `.+`},
		{Type: "header", Name: "Via", Pattern: `Varnish`},
	},
}
