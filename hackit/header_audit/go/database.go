package main

import "strings"

var HeaderDatabase = map[string]struct {
	Description string
	Category    string
}{
	"strict-transport-security": {"Enforces HTTPS connections to prevent man-in-the-middle attacks.", "Security"},
	"content-security-policy":   {"Defines allowed resources to prevent XSS and injection attacks.", "Security"},
	"x-frame-options":           {"Indicates if a browser should be allowed to render a page in a <frame>.", "Security"},
	"x-content-type-options":    {"Prevents the browser from MIME-sniffing the response away from the declared content-type.", "Security"},
	"referrer-policy":           {"Governs which referrer information should be included with requests made.", "Security"},
	"permissions-policy":        {"Controls which browser features (camera, mic) can be used.", "Security"},
	"x-xss-protection":          {"Enables XSS filtering in legacy browsers.", "Security"},
	"cache-control":             {"Directives for caching mechanisms in both browsers and shared caches.", "Caching"},
	"server":                    {"Identifies the software used by the origin server.", "Information"},
	"x-powered-by":              {"Specifies the technology (e.g., ASP.NET, PHP) supporting the application.", "Information"},
	"set-cookie":                {"Sets a cookie for the user agent.", "Session"},
	"access-control-allow-origin": {"Indicates whether the response can be shared with requesting code from the given origin.", "Security/CORS"},
	"content-type":              {"Indicates the media type of the resource.", "Content"},
	"content-length":            {"The length of the response body in octets.", "Content"},
}

func GetHeaderMetadata(key string) (string, string) {
	k := strings.ToLower(key)
	if meta, ok := HeaderDatabase[k]; ok {
		return meta.Description, meta.Category
	}
	return "General HTTP response header.", "General"
}
