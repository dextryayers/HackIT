package main

import "regexp"

var endpointPatterns = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	// -- Core API Routes --
	{"API Route", regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]+api[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"API Route (relative)", regexp.MustCompile(`["'\` + "`" + `](/api/[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"GraphQL Endpoint", regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*(graphql|gql|query)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"GraphQL (relative)", regexp.MustCompile(`["'\` + "`" + `](/[^"'\` + "`" + `\s]*(graphql|gql)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"GraphQL Subscriptions", regexp.MustCompile(`["'\` + "`" + `](wss?://[^"'\` + "`" + `\s]*(?:subscriptions?|graphql-ws)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"tRPC Endpoint", regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*\.trpc[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"tRPC (relative)", regexp.MustCompile(`["'\` + "`" + `](/[^"'\` + "`" + `\s]*(?:trpc|api/trpc)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"gRPC-Web Endpoint", regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*(?:grpc|grpcweb|grpc-web)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"SSE Endpoint", regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*(?:sse|events?|stream|push|notify|server-sent-events)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"REST Resource", regexp.MustCompile(`["'\` + "`" + `](/[^"'\` + "`" + `\s]*(?:users|admin|auth|login|register|oauth|token|v1|v2|v3|rest|soap)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"RPC Endpoint", regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*(rpc|jsonrpc|xmlrpc|grpc)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},

	// -- WebSocket / Real-time --
	{"WebSocket", regexp.MustCompile(`["'\` + "`" + `](wss?://[^"'\` + "`" + `\s]+)["'\` + "`" + `]`)},
	{"WebSocket (relative)", regexp.MustCompile(`["'\` + "`" + `]/(?:socket|socket\.io|ws|wss|events|comet|chat|realtime|stream|push)[^"'\` + "`" + `\s]*["'\` + "`" + `]`)},
	{"WebRTC STUN/TURN", regexp.MustCompile(`["'\` + "`" + `](stun:|turn:)[^"'\` + "`" + `]+["'\` + "`" + `]`)},

	// -- Cloud Storage & CDN --
	{"AWS S3 Bucket", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.s3\.amazonaws\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"AWS S3 (dualstack)", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.s3\.dualstack\.[a-z0-9\-]+\.amazonaws\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"AWS S3 (regional)", regexp.MustCompile(`["'\` + "`" + `](https?://s3[-.][a-z0-9\-]+\.amazonaws\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"CloudFront CDN", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.cloudfront\.net[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Azure Blob Storage", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.blob\.core\.windows\.net[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Azure CDN", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.azureedge\.net[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"GCP Cloud Storage", regexp.MustCompile(`["'\` + "`" + `](https?://storage\.googleapis\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"GCP Cloud Storage (bucket)", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.storage\.googleapis\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Cloudflare R2", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.r2\.cloudflarestorage\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"DigitalOcean Spaces", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.(?:nyc3|ams3|sfo3|sgp1)\.digitaloceanspaces\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Backblaze B2", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.backblazeb2\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Wasabi S3", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.s3\.wasabisys\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Alibaba OSS", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.oss-[a-z-]+\.aliyuncs\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},

	// -- Serverless & Edge --
	{"Vercel Deployment", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.vercel\.app[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Netlify Deployment", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.netlify\.app[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Netlify Functions", regexp.MustCompile(`["'\` + "`" + `](/\.netlify/functions/[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Cloudflare Worker", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.workers\.dev[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Cloudflare Pages", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.pages\.dev[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Deno Deploy", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.deno\.dev[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Fly.io", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.fly\.dev[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Railway", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.railway\.app[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Render", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.onrender\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"GitHub Pages", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.github\.io[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"AWS Lambda URL", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.lambda-url\.[a-z0-9\-]+\.on\.aws[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},

	// -- Database & Backend --
	{"Supabase URL", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.supabase\.co[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Supabase Edge Function", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.supabase\.co/functions[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Firebase URL", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.firebase(?:io|app)\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"MongoDB Atlas", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.mongodb\.net[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"PlanetScale", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.psdb\.cloud[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Neon DB", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.neon\.tech[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Convex Backend", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.convex\.cloud[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},

	// -- OAuth & Identity --
	{"Auth0 Domain", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.auth0\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Okta Domain", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.okta\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Okta (relative)", regexp.MustCompile(`["'\` + "`" + `](/oauth2/[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"AWS Cognito", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]*\.auth\.[a-z0-9\-]+\.amazoncognito\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Keycloak Realm", regexp.MustCompile(`["'\` + "`" + `](/[^"'\` + "`" + `\s]*(?:auth|realms|keycloak)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Clerk Auth", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.clerk\.accounts\.dev[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Stytch Auth", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.stytch\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"WorkOS", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.workos\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},

	// -- Payment & Fintech --
	{"Stripe API", regexp.MustCompile(`["'\` + "`" + `](https?://api\.stripe\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Stripe Checkout", regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*checkout\.stripe\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"PayPal API", regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*(?:api\.paypal|api-m\.paypal|paypal\.com)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Square API", regexp.MustCompile(`["'\` + "`" + `](https?://connect\.squareup\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Paddle API", regexp.MustCompile(`["'\` + "`" + `](https?://vendors\.paddle\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Lemon Squeezy", regexp.MustCompile(`["'\` + "`" + `](https?://api\.lemonsqueezy\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},

	// -- Monitoring & Observability --
	{"Sentry DSN", regexp.MustCompile(`["'\` + "`" + `](https?://[a-f0-9]{32}@[a-f0-9]{9,16}\.ingest\.sentry\.io[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Datadog Site", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.datadoghq\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"New Relic", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.newrelic\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"OpenTelemetry", regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*(?:otel|opentelemetry|tempo)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},

	// -- Internal / Private Network --
	{"Internal Host", regexp.MustCompile(`["'\` + "`" + `](https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Internal Domain", regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*(?:\.internal|\.local|intranet|corp|private)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Kubernetes Service", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z0-9\-]+\.svc\.cluster\.local[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},

	// -- General --
	{"Absolute URL", regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s/]+/[^"'\` + "`" + `\s"']+)["'\` + "`" + `]`)},
	{"Relative Path", regexp.MustCompile(`["'\` + "`" + `](/[a-zA-Z][a-zA-Z0-9\-_./]+)["'\` + "`" + `]`)},
	{"CDN URL", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.(?:cloudfront|cdn|akamai|fastly)\.net[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Callback URL", regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*(?:callback|redirect|return|continue|next|goto)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Webhook URL", regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*(?:webhook|hook|callback|notify)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"OAuth URL", regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*(?:oauth|authorize|authenticate|sso|saml|openid)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Upload Endpoint", regexp.MustCompile(`["'\` + "`" + `](/[^"'\` + "`" + `\s]*(?:upload|download|file|media|attach|image)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Proxy Endpoint", regexp.MustCompile(`["'\` + "`" + `](/[^"'\` + "`" + `\s]*(?:proxy|redirect|forward|fetch|cors)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Debug Endpoint", regexp.MustCompile(`["'\` + "`" + `](/[^"'\` + "`" + `\s]*(?:debug|dev|test|staging|sandbox|swagger|docs|health|status|metrics)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Package Registry", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.(?:npmjs|pypi|rubygems)\.org[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Container Registry", regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.(?:docker|gcr|ecr|quay)\.(?:io|com)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
}

type EndpointResult struct {
	URL  string `json:"url"`
	Type string `json:"type"`
}

func extractEndpoints(content string) []EndpointResult {
	var results []EndpointResult
	seen := make(map[string]bool)
	for _, ep := range endpointPatterns {
		matches := ep.Pattern.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if len(m) >= 2 {
				u := m[1]
				if !seen[u] {
					seen[u] = true
					results = append(results, EndpointResult{URL: u, Type: ep.Name})
				}
			}
		}
	}
	return results
}

var importPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?:import|require)\s*\(?\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*\)?`),
	regexp.MustCompile(`(?:from|import)\s+["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`),
	regexp.MustCompile(`new\s+(?:Worker|SharedWorker)\s*\(?\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`),
	regexp.MustCompile(`import\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*\)`),
	regexp.MustCompile(`new\s+URL\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`),
	regexp.MustCompile(`import\.meta\.resolve\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*\)`),
	regexp.MustCompile(`import\.meta\.glob\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*\)`),
	regexp.MustCompile(`importScripts\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*\)`),
	regexp.MustCompile(`require\.resolve\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*\)`),
	regexp.MustCompile(`require\.context\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`),
	regexp.MustCompile(`System\.import\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`),
	regexp.MustCompile(`System\.register\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`),
}

func extractImports(content string) []string {
	var results []string
	seen := make(map[string]bool)
	for _, re := range importPatterns {
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if len(m) >= 2 {
				p := m[1]
				if !seen[p] {
					seen[p] = true
					results = append(results, p)
				}
			}
		}
	}
	return results
}
