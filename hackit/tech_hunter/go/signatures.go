package main

type Signature struct {
	Type    string `json:"type"` // meta, header, cookie, script, html, url, style
	Name    string `json:"name,omitempty"`
	Pattern string `json:"pattern"`
}

var Technologies = map[string][]Signature{
	"WordPress": {
		{Type: "meta", Pattern: `name="generator" content="WordPress ?([0-9.]*)`},
		{Type: "url", Pattern: `wp-content/`},
		{Type: "url", Pattern: `wp-includes/`},
		{Type: "script", Pattern: `wp-includes/js/`},
		{Type: "html", Pattern: `wp-json`},
	},
	"Joomla": {
		{Type: "meta", Pattern: `name="generator" content="Joomla! - Open Source Content Management`},
		{Type: "url", Pattern: `index.php\?option=com_`},
		{Type: "header", Name: "X-Content-Encoded-By", Pattern: `Joomla`},
	},
	"Drupal": {
		{Type: "meta", Pattern: `name="Generator" content="Drupal ([0-9]*)`},
		{Type: "header", Name: "X-Generator", Pattern: `Drupal ?([0-9]*)`},
		{Type: "url", Pattern: `sites/all/themes`},
	},
	"Laravel": {
		{Type: "cookie", Pattern: `laravel_session`},
		{Type: "header", Name: "Set-Cookie", Pattern: `laravel_session`},
		{Type: "header", Name: "X-Powered-By", Pattern: `Laravel`},
	},
	"Django": {
		{Type: "cookie", Pattern: `csrftoken`},
		{Type: "html", Pattern: `csrfmiddlewaretoken`},
	},
	"Ruby on Rails": {
		{Type: "meta", Pattern: `name="csrf-param" content="authenticity_token"`},
		{Type: "header", Name: "X-Powered-By", Pattern: `Phusion Passenger`},
	},
	"Spring Boot": {
		{Type: "header", Name: "X-Application-Context", Pattern: `.*`},
	},
	"React": {
		{Type: "script", Pattern: `react`},
		{Type: "html", Pattern: `data-reactroot`},
	},
	"Vue.js": {
		{Type: "script", Pattern: `vue`},
		{Type: "html", Pattern: `data-v-`},
	},
	"Angular": {
		{Type: "html", Pattern: `ng-app`},
		{Type: "html", Pattern: `ng-controller`},
	},
	"jQuery": {
		{Type: "script", Pattern: `jquery.*\.js`},
	},
	"Bootstrap": {
		{Type: "script", Pattern: `bootstrap.*\.js`},
		{Type: "style", Pattern: `bootstrap.*\.css`},
	},
	"Nginx": {
		{Type: "header", Name: "Server", Pattern: `nginx/?([0-9.]*)?`},
	},
	"Apache": {
		{Type: "header", Name: "Server", Pattern: `Apache/?([0-9.]*)?`},
	},
	"IIS": {
		{Type: "header", Name: "Server", Pattern: `IIS/?([0-9.]*)?`},
	},
	"PHP": {
		{Type: "header", Name: "X-Powered-By", Pattern: `PHP/?([0-9.]*)?`},
		{Type: "cookie", Pattern: `PHPSESSID`},
	},
	"Cloudflare": {
		{Type: "header", Name: "Server", Pattern: `cloudflare`},
		{Type: "header", Name: "CF-RAY", Pattern: `.+`},
	},
	"AWS": {
		{Type: "header", Name: "Server", Pattern: `AmazonS3`},
		{Type: "header", Name: "X-Amz-Id", Pattern: `.+`},
	},
	"Google": {
		{Type: "header", Name: "Server", Pattern: `gws`},
		{Type: "cookie", Pattern: `1P_JAR`},
		{Type: "cookie", Pattern: `NID`},
	},
	"Google Search": {
		{Type: "html", Pattern: `name="google"`},
	},
}
