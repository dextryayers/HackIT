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
		{Type: "header", Name: "X-LiteSpeed-Cache", Pattern: `.+`},
	},
	"PHP": {
		{Type: "header", Name: "X-Powered-By", Pattern: `PHP/?([0-9.]*)?`},
		{Type: "cookie", Pattern: `PHPSESSID`},
	},
	"Laravel": {
		{Type: "cookie", Pattern: `laravel_session`},
		{Type: "cookie", Pattern: `XSRF-TOKEN`},
		{Type: "header", Name: "X-Powered-By", Pattern: `Laravel`},
	},
	"WordPress": {
		{Type: "meta", Pattern: `name="generator" content="WordPress ?([0-9.]*)`},
		{Type: "url", Pattern: `wp-content/`},
		{Type: "url", Pattern: `wp-includes/`},
		{Type: "header", Name: "X-Pingback", Pattern: `.*xmlrpc\.php`},
	},
	"Cloudflare": {
		{Type: "header", Name: "CF-RAY", Pattern: `.+`},
		{Type: "header", Name: "Server", Pattern: `cloudflare`},
		{Type: "header", Name: "cf-cache-status", Pattern: `.+`},
	},
	"Next.js": {
		{Type: "script", Pattern: `_next/static`},
		{Type: "html", Pattern: `__NEXT_DATA__`},
		{Type: "header", Name: "X-Nextjs-Cache", Pattern: `.+`},
	},
	"React": {
		{Type: "script", Pattern: `react\.production\.min\.js`},
		{Type: "html", Pattern: `data-reactroot`},
		{Type: "html", Pattern: `_reactListening`},
	},
	"Vue.js": {
		{Type: "script", Pattern: `vue\.js`},
		{Type: "html", Pattern: `__vue__`},
		{Type: "html", Pattern: `data-v-`},
	},
	"Fastly": {
		{Type: "header", Name: "X-Served-By", Pattern: `cache-`},
		{Type: "header", Name: "X-Cache", Pattern: `HIT`},
	},
	"Cloudfront": {
		{Type: "header", Name: "X-Amz-Cf-Id", Pattern: `.+`},
		{Type: "header", Name: "Via", Pattern: `CloudFront`},
	},
	"Express": {
		{Type: "header", Name: "X-Powered-By", Pattern: `Express`},
		{Type: "cookie", Pattern: `connect.sid`},
	},
	"Django": {
		{Type: "cookie", Pattern: `csrftoken`},
		{Type: "html", Pattern: `csrfmiddlewaretoken`},
	},
	"jQuery": {
		{Type: "script", Pattern: `jquery(?:\.min)?\.js`},
		{Type: "html", Pattern: `jQuery`},
	},
	"Bootstrap": {
		{Type: "html", Pattern: `bootstrap(?:\.min)?\.css`},
		{Type: "script", Pattern: `bootstrap(?:\.min)?\.js`},
	},
	"Tailwind CSS": {
		{Type: "html", Pattern: `tailwind`},
	},
	"GSAP": {
		{Type: "script", Pattern: `gsap(?:\.min)?\.js`},
		{Type: "html", Pattern: `TweenMax|TweenLite|TimelineMax`},
	},
	"Astro": {
		{Type: "html", Pattern: `astro-island|astro-`},
	},
}
