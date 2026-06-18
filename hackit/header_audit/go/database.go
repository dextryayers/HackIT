package main

import (
	"crypto/tls"
	"strings"
)

type HeaderMeta struct {
	Description string
	Category    string
}

var HeaderDatabase = map[string]HeaderMeta{
	"strict-transport-security":       {"Enforces HTTPS connections to prevent man-in-the-middle attacks", "Security"},
	"content-security-policy":         {"Defines allowed resources to prevent XSS and injection attacks", "Security"},
	"x-frame-options":                 {"Indicates if a browser should be allowed to render a page in a <frame>", "Security"},
	"x-content-type-options":          {"Prevents MIME-sniffing attacks", "Security"},
	"referrer-policy":                 {"Controls how much referrer information is sent with requests", "Security"},
	"permissions-policy":              {"Controls which browser features can be used", "Security"},
	"x-xss-protection":                {"Enables XSS filtering in legacy browsers (deprecated)", "Security"},
	"cross-origin-embedder-policy":    {"Requires cross-origin resources to be explicitly granted", "Security"},
	"cross-origin-opener-policy":      {"Controls cross-origin window interactions", "Security"},
	"cross-origin-resource-policy":    {"Controls which origins can load this resource", "Security"},
	"access-control-allow-origin":     {"Indicates whether the response can be shared via CORS", "Security/CORS"},
	"access-control-allow-methods":    {"Specifies methods allowed for cross-origin requests", "Security/CORS"},
	"access-control-allow-headers":    {"Specifies headers allowed for cross-origin requests", "Security/CORS"},
	"access-control-allow-credentials": {"Indicates whether credentials are exposed via CORS", "Security/CORS"},
	"access-control-expose-headers":   {"Specifies which headers can be exposed via CORS", "Security/CORS"},
	"access-control-max-age":          {"Indicates how long preflight results can be cached", "Security/CORS"},
	"access-control-request-private-network": {"Indicates private network access request", "Security/CORS"},
	"x-dns-prefetch-control":          {"Controls DNS prefetching for privacy/security", "Security"},
	"cache-control":                   {"Directives for caching mechanisms in browsers and proxies", "Caching"},
	"pragma":                          {"Implementation-specific header, often used for cache control", "Caching"},
	"expires":                         {"The date/time after which the response is considered stale", "Caching"},
	"age":                             {"The time in seconds the object has been in a proxy cache", "Caching"},
	"vary":                            {"Tells downstream caches how to match future request headers", "Caching"},
	"server":                          {"Identifies the server software", "Information"},
	"x-powered-by":                    {"Specifies the technology supporting the application", "Information"},
	"x-aspnet-version":                {"Exposes ASP.NET version information", "Information Leak"},
	"x-aspnetmvc-version":             {"Exposes ASP.NET MVC version", "Information Leak"},
	"x-generator":                     {"Exposes CMS/framework generator info", "Information Leak"},
	"x-debug-token":                   {"Exposes Symfony debug token (dev mode)", "Information Leak"},
	"x-debug-exception":               {"Exposes debug exception details", "Information Leak"},
	"x-served-by":                     {"Exposes hostname/internal server info", "Information Leak"},
	"x-runtime":                       {"Exposes Ruby/Rails request processing time", "Information Leak"},
	"x-version":                       {"Exposes application version", "Information Leak"},
	"via":                             {"Proxies add Via header showing intermediate servers", "Information Leak"},
	"set-cookie":                      {"Sends cookies from the server to the user agent", "Session"},
	"content-type":                    {"Indicates the media type of the resource", "Content"},
	"content-length":                  {"The length of the response body in bytes", "Content"},
	"content-encoding":                {"The encoding/compression algorithm used on the data", "Content"},
	"content-language":                {"Describes the natural language(s) of the resource", "Content"},
	"content-location":                {"Indicates an alternate location for the returned data", "Content"},
	"date":                            {"The date and time the message was sent", "Network"},
	"connection":                      {"Controls whether the network connection stays open", "Network"},
	"transfer-encoding":               {"The form of encoding used to transfer the payload body", "Network"},
	"accept-ranges":                   {"Indicates if the server supports range requests", "Network"},
	"location":                        {"Indicates the URL to redirect a page to", "Network"},
	"alt-svc":                         {"Indicates alternative services that can be reached", "Network"},
	"etag":                            {"Identifier for a specific version of a resource", "Caching"},
	"last-modified":                   {"The last modified date of the resource", "Caching"},
	"www-authenticate":                {"Indicates the authentication scheme for 401 responses", "Security"},
	"x-robots-tag":                    {"Controls how search engines index the page", "Content"},
	"x-request-id":                    {"Unique request identifier for debugging/tracing", "Network"},
	"x-trace-id":                      {"Trace identifier for distributed tracing", "Network"},
	"clear-site-data":                 {"Clears browsing data for the requesting origin", "Security"},
	"report-to":                       {"Specifies reporting endpoint group for CSP/COOP reports", "Security"},
	"nel":                             {"Network Error Logging policy", "Security"},
	"expect-ct":                       {"Enables Certificate Transparency enforcement (deprecated)", "Security"},
}

func GetHeaderMetadata(key string) (string, string) {
	k := strings.ToLower(key)
	if meta, ok := HeaderDatabase[k]; ok {
		return meta.Description, meta.Category
	}
	return "General HTTP response header", "General"
}

func parseInt(s string) (int, error) {
	var n int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			break
		}
	}
	return n, nil
}

func tlsVersionStringGo(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}
