package main

// Header definition
type HeaderDef struct {
	Name           string
	Description    string
	Recommendation string
	SafeValue      string // Expected value substring (optional)
}

var SecurityHeaders = []HeaderDef{
	{"Strict-Transport-Security", "Enforces HTTPS connections", "max-age=31536000; includeSubDomains", ""},
	{"Content-Security-Policy", "Prevents XSS and other injection attacks", "default-src 'self'", ""},
	{"X-Frame-Options", "Prevents Clickjacking", "DENY or SAMEORIGIN", ""},
	{"X-Content-Type-Options", "Prevents MIME-sniffing", "nosniff", "nosniff"},
	{"Referrer-Policy", "Controls Referrer information", "strict-origin-when-cross-origin", ""},
	{"Permissions-Policy", "Controls browser features", "geolocation=()", ""},
	{"X-XSS-Protection", "Legacy XSS protection (deprecated but sometimes useful)", "1; mode=block", ""},
}

var DangerousHeaders = []HeaderDef{
	{"Server", "Leaks server software version", "Remove or obscure this header", ""},
	{"X-Powered-By", "Leaks underlying technology", "Remove this header", ""},
	{"X-AspNet-Version", "Leaks ASP.NET version", "Remove this header", ""},
	{"X-Generator", "Leaks CMS generator", "Remove this header", ""},
}
