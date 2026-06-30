package main

import "regexp"

var endpointPatterns = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	{"API Route", regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]+api[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"API Route (relative)", regexp.MustCompile(`["'\` + "`" + `](/api/[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"GraphQL Endpoint", regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*(graphql|gql|query)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"GraphQL (relative)", regexp.MustCompile(`["'\` + "`" + `](/[^"'\` + "`" + `\s]*(graphql|gql)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"tRPC Endpoint", regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*\.trpc[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"tRPC (relative)", regexp.MustCompile(`["'\` + "`" + `](/[^"'\` + "`" + `\s]*(?:trpc|api/trpc)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"WebSocket", regexp.MustCompile(`["'\` + "`" + `](wss?://[^"'\` + "`" + `\s]+)["'\` + "`" + `]`)},
	{"AWS S3 Bucket", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.s3\.amazonaws\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"CloudFront CDN", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.cloudfront\.net[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Azure Blob Storage", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.blob\.core\.windows\.net[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"GCP Cloud Storage", regexp.MustCompile(`["'\` + "`" + `](https?://storage\.googleapis\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Cloudflare R2", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.r2\.cloudflarestorage\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Vercel Deployment", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.vercel\.app[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Netlify Deployment", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.netlify\.app[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Cloudflare Worker", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.workers\.dev[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Supabase URL", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.supabase\.co[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Firebase URL", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.firebase(?:io|app)\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"MongoDB Atlas", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.mongodb\.net[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Auth0 Domain", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.auth0\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Okta Domain", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.okta\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Stripe API", regexp.MustCompile(`["'\` + "`" + `](https?://api\.stripe\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"PayPal API", regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*(?:api\.paypal|api-m\.paypal|paypal\.com)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Sentry DSN", regexp.MustCompile(`["'\` + "`" + `](https?://[a-f0-9]{32}@[a-f0-9]{9,16}\.ingest\.sentry\.io[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Internal Host", regexp.MustCompile(`["'\` + "`" + `](https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Kubernetes Service", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z0-9\-]+\.svc\.cluster\.local[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Callback URL", regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*(?:callback|redirect|return|continue|next|goto)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Webhook URL", regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*(?:webhook|hook|callback|notify)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"OAuth URL", regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*(?:oauth|authorize|authenticate|sso|saml|openid)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Upload Endpoint", regexp.MustCompile(`["'\` + "`" + `](/[^"'\` + "`" + `\s]*(?:upload|download|file|media|attach|image)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Proxy Endpoint", regexp.MustCompile(`["'\` + "`" + `](/[^"'\` + "`" + `\s]*(?:proxy|redirect|forward|fetch|cors)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Debug Endpoint", regexp.MustCompile(`["'\` + "`" + `](/[^"'\` + "`" + `\s]*(?:debug|dev|test|staging|sandbox|swagger|docs|health|status|metrics)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
}

func extractEndpoints(content string) []EndpointResult {
	var results []EndpointResult
	seen := make(map[string]bool)
	for _, ep := range endpointPatterns {
		matches := ep.Pattern.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if len(m) >= 2 && !seen[m[1]] {
				seen[m[1]] = true
				results = append(results, EndpointResult{URL: m[1], Type: ep.Name})
			}
		}
	}
	return results
}
