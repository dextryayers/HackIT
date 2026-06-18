package main

import "regexp"

type SensitiveFinding struct {
	Name    string `json:"name"`
	Match   string `json:"match"`
	Line    int    `json:"line,omitempty"`
}

type sensitivePattern struct {
	Name    string
	Pattern *regexp.Regexp
	Context int
}

var sensitivePatterns = []sensitivePattern{
	// -- AWS --
	{"AWS Access Key ID", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), 0},
	{"AWS Secret Access Key", regexp.MustCompile(`(?i)aws.{0,20}["\'][0-9a-zA-Z\/+]{40}["\']`), 1},
	{"AWS Session Token", regexp.MustCompile(`(?i)aws.{0,30}(?:session.?token|security.?token)[:=]\s*["\'][A-Za-z0-9+/=]{40,}["\']`), 1},
	{"AWS AppSync Key", regexp.MustCompile(`da2-[a-zA-Z0-9]{26}`), 0},
	{"AWS Cognito ID", regexp.MustCompile(`(?i)cognito.{0,20}(?:client.?id|pool.?id|identity.?pool.?id)[:=]\s*["\'][a-zA-Z0-9_\-]+["\']`), 1},
	{"AWS S3 Bucket", regexp.MustCompile(`[a-zA-Z0-9\-_\.]+\.s3\.amazonaws\.com`), 0},
	{"AWS S3 URL", regexp.MustCompile(`s3://[a-zA-Z0-9\-_]+`), 0},

	// -- GCP --
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), 0},
	{"Google OAuth Client ID", regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`), 0},
	{"Google OAuth Secret", regexp.MustCompile(`["\'][0-9a-zA-Z\-_]{24}["\']`), 1},
	{"GCP Service Account (inline)", regexp.MustCompile(`(?i)"type"\s*:\s*"service_account"`), 0},
	{"GCP Private Key ID", regexp.MustCompile(`(?i)"private_key_id"\s*:\s*"[a-f0-9]{40}"`), 0},
	{"GCP Client Email", regexp.MustCompile(`[a-zA-Z0-9\-_]+@[a-zA-Z0-9\-_]+\.iam\.gserviceaccount\.com`), 0},
	{"GCP Project ID", regexp.MustCompile(`(?i)"project_id"\s*:\s*"[a-z0-9\-]{6,30}"`), 0},

	// -- Azure --
	{"Azure Storage Key", regexp.MustCompile(`(?i)(?:azure|storage).{0,20}(?:account.?key|access.?key)[:=]\s*["\'][a-zA-Z0-9+/=]{86,88}["\']`), 1},
	{"Azure Connection String", regexp.MustCompile(`(?i)DefaultEndpointsProtocol=https;AccountName=[a-zA-Z0-9]+;AccountKey=[a-zA-Z0-9+/=]{86,88}`), 0},
	{"Azure Tenant ID", regexp.MustCompile(`(?i)(?:tenant.?id)[:=]\s*["\'][a-z0-9\-]{36}["\']`), 0},
	{"Azure Client ID", regexp.MustCompile(`(?i)(?:client.?id)[:=]\s*["\'][a-z0-9\-]{36}["\']`), 0},
	{"Azure DevOps PAT", regexp.MustCompile(`(?i)azure.?devops.{0,20}(?:token|pat)[:=]\s*["\'][a-zA-Z0-9]{52}["\']`), 1},

	// -- Alibaba Cloud --
	{"Alibaba Access Key", regexp.MustCompile(`LTAI[a-zA-Z0-9]{12,20}`), 0},
	{"Alibaba Secret", regexp.MustCompile(`(?i)(?:aliyun|alibaba).{0,20}(?:access.?key|secret.?key)[:=]\s*["\'][a-zA-Z0-9]+["\']`), 1},

	// -- DigitalOcean / Linode / Vultr --
	{"DigitalOcean Token", regexp.MustCompile(`dop_v1_[a-zA-Z0-9_\-]{64}`), 0},
	{"DigitalOcean API Key", regexp.MustCompile(`(?i)(?:digitalocean|do).{0,20}(?:token|api.?key)[:=]\s*["\'][a-zA-Z0-9_\-]{64}["\']`), 1},
	{"Linode Token", regexp.MustCompile(`(?i)(?:linode).{0,20}(?:token|api.?key)[:=]\s*["\'][a-zA-Z0-9]{64}["\']`), 1},

	// -- AI / ML APIs --
	{"OpenAI API Key", regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`), 0},
	{"OpenAI Org ID", regexp.MustCompile(`(?i)(?:openai|oai).{0,20}(?:org.?id|organization)[:=]\s*["\'][a-zA-Z0-9_\-]+["\']`), 1},
	{"Anthropic API Key", regexp.MustCompile(`sk-ant-[a-zA-Z0-9]{20,}`), 0},
	{"HuggingFace Token", regexp.MustCompile(`hf_[a-zA-Z0-9]{34,}`), 0},
	{"Replicate API Token", regexp.MustCompile(`r8_[a-zA-Z0-9_\-]{36,}`), 0},
	{"Cohere API Key", regexp.MustCompile(`(?i)cohere.{0,20}(?:api.?key|token)[:=]\s*["\'][a-zA-Z0-9_\-]+["\']`), 1},
	{"Stability AI Key", regexp.MustCompile(`(?i)stability.{0,20}(?:api.?key|token)[:=]\s*["\'][a-zA-Z0-9_\-]+["\']`), 1},
	{"ElevenLabs API Key", regexp.MustCompile(`(?i)eleven.?labs.{0,20}(?:api.?key)[:=]\s*["\'][a-zA-Z0-9_\-]+["\']`), 1},
	{"Gemini API Key", regexp.MustCompile(`(?i)(?:gemini|vertex).{0,20}(?:api.?key|project.?id)[:=]\s*["\'][a-zA-Z0-9_\-]+["\']`), 1},

	// -- Slack / Discord --
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z\-]{10,}`), 0},
	{"Slack Bot Token", regexp.MustCompile(`xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9\-_]{24}`), 0},
	{"Slack Webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9+/]{44,46}`), 0},
	{"Discord Webhook", regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+`), 0},

	// -- GitHub / GitLab / Bitbucket --
	{"GitHub Token (new)", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`), 0},
	{"GitHub Fine-Grained PAT", regexp.MustCompile(`github_pat_[a-zA-Z0-9_]{22,}`), 0},
	{"GitHub Token (old)", regexp.MustCompile(`[0-9a-f]{40}`), 1},
	{"GitLab Token", regexp.MustCompile(`glpat-[A-Za-z0-9\-_]{20,}`), 0},
	{"GitLab CI Job Token", regexp.MustCompile(`glcbt-[a-zA-Z0-9_\-]{20,}`), 0},
	{"Bitbucket App Password", regexp.MustCompile(`(?i)bitbucket.{0,20}(?:app.?password|token|oauth)[:=]\s*["\'][a-zA-Z0-9_\-]+["\']`), 1},

	// -- Stripe / Payments --
	{"Stripe Live Secret", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`), 0},
	{"Stripe Test Secret", regexp.MustCompile(`sk_test_[0-9a-zA-Z]{24,}`), 0},
	{"Stripe Public Key", regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`), 0},
	{"Stripe Webhook Secret", regexp.MustCompile(`whsec_[0-9a-zA-Z]{24,}`), 0},

	// -- Email / SMS APIs --
	{"SendGrid API Key", regexp.MustCompile(`SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}`), 0},
	{"Mailgun API Key", regexp.MustCompile(`key-[a-f0-9]{32}`), 0},
	{"Mailchimp API Key", regexp.MustCompile(`[a-f0-9]{32}-us[0-9]{1,2}`), 0},
	{"Twilio Account SID", regexp.MustCompile(`AC[a-f0-9]{32}`), 0},
	{"Twilio Auth Token", regexp.MustCompile(`(?i)twilio.{0,20}(?:auth.?token|api.?key|api.?secret)[:=]\s*["\'][a-zA-Z0-9_\-]+["\']`), 1},
	{"Vonage API Key", regexp.MustCompile(`(?i)(?:vonage|nexmo).{0,20}(?:api.?key|api.?secret)[:=]\s*["\'][a-zA-Z0-9]+["\']`), 1},

	// -- Auth / Identity --
	{"Auth0 Client ID", regexp.MustCompile(`(?i)auth0.{0,20}(?:client.?id|client.?secret|domain|audience)[:=]\s*["\'][a-zA-Z0-9_\-\.]+["\']`), 1},
	{"Clerk Secret Key", regexp.MustCompile(`sk_test_[a-zA-Z0-9_\-]{20,}`), 0},
	{"Supabase Anon Key", regexp.MustCompile(`(?i)supabase.{0,20}(?:anon.?key|service.?role.?key|url|project.?ref)[:=]\s*["\'][a-zA-Z0-9_\-]+["\']`), 1},
	{"Supabase JWT", regexp.MustCompile(`eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+`), 0},
	{"Firebase Database", regexp.MustCompile(`[a-zA-Z0-9\-_]+\.firebaseio\.com`), 0},
	{"Firebase App", regexp.MustCompile(`[a-zA-Z0-9\-_]+\.firebaseapp\.com`), 0},

	// -- JWT / Tokens --
	{"JWT Token", regexp.MustCompile(`eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+`), 0},
	{"Bearer Token", regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}`), 1},
	{"JWT Secret", regexp.MustCompile(`(?i)(?:jwt|jws).{0,20}(?:secret|key|signing.?key|private.?key)[:=]\s*["\'][a-zA-Z0-9_\-+/=]{8,}["\']`), 1},
	{"CSRF/Session Key", regexp.MustCompile(`(?i)(?:csrf|encryption|session).{0,10}(?:key|secret|token)[:=]\s*["\'][a-zA-Z0-9_\-+/=]{8,}["\']`), 1},

	// -- Private Keys --
	{"RSA Private Key", regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`), 0},
	{"EC Private Key", regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`), 0},
	{"OpenSSH Private Key", regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`), 0},
	{"PGP Private Key", regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`), 0},
	{"Generic Private Key", regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`), 0},
	{"DSA Private Key", regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`), 0},
	{"SSH Private Key", regexp.MustCompile(`-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----`), 0},

	// -- Database Connection Strings --
	{"MongoDB Connection", regexp.MustCompile(`mongodb(?:\+srv)?://[^\s"\'<>]+`), 0},
	{"PostgreSQL Connection", regexp.MustCompile(`postgres(?:ql)?(?:\+srv)?://[^\s"\'<>]+`), 0},
	{"MySQL Connection", regexp.MustCompile(`mysql(?:\+[a-z]+)?://[^\s"\'<>]+`), 0},
	{"Redis Connection", regexp.MustCompile(`redis(?:s|sentinel)?://[^\s"\'<>]+`), 0},
	{"RabbitMQ Connection", regexp.MustCompile(`amqps?://[^\s"\'<>]+`), 0},
	{"JDBC Connection", regexp.MustCompile(`jdbc:(?:mysql|postgresql|oracle|sqlserver|h2|sqlite)://[^\s"\'<>]+`), 0},
	{"SQLite Connection", regexp.MustCompile(`sqlite(?:3)?://[^\s"\'<>]+`), 0},
	{"Elasticsearch Connection", regexp.MustCompile(`(?i)elastic.?search.{0,20}(?:url|host|cloud.?id)[:=]\s*["\'][a-zA-Z0-9_\-\.:\/]+["\']`), 1},
	{"CockroachDB Connection", regexp.MustCompile(`(?i)cockroach.{0,20}(?:connection.?string|url|password)[:=]\s*["\'][a-zA-Z0-9_\-]+["\']`), 1},
	{"FaunaDB Secret", regexp.MustCompile(`fn[A-Za-z0-9_\-]{40,}`), 0},

	// -- CI/CD & Package Registries --
	{"npm Token", regexp.MustCompile(`npm_[A-Za-z0-9]{36,}`), 0},
	{"NPM Token (old)", regexp.MustCompile(`//registry\.npmjs\.org/:_authToken=[A-Za-z0-9\-_]+`), 0},
	{"PyPI Token", regexp.MustCompile(`pypi-[a-zA-Z0-9_\-]{40,}`), 0},
	{"RubyGems Key", regexp.MustCompile(`rubygems_[a-f0-9]{48}`), 0},
	{"Docker Hub Token", regexp.MustCompile(`dcp_[a-zA-Z0-9_\-]{40,}`), 0},
	{"Terraform Token", regexp.MustCompile(`(?i)terraform.{0,20}(?:token|api.?key)[:=]\s*["\'][a-zA-Z0-9_\-]+["\']`), 1},
	{"Pulumi Token", regexp.MustCompile(`pul-[a-f0-9]{40}`), 0},
	{"Heroku API Key", regexp.MustCompile(`[hH][eE][rR][oO][kK][uU].{0,20}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`), 1},

	// -- Monitoring / Observability --
	{"Sentry DSN", regexp.MustCompile(`https://[a-f0-9]{32}@[a-f0-9]{9,16}\.ingest\.sentry\.io`), 0},
	{"Datadog API Key", regexp.MustCompile(`datadog_api_key\s*[:=]\s*["\'][a-zA-Z0-9]{32}["\']`), 1},
	{"Datadog App Key", regexp.MustCompile(`(?i)datadog.{0,20}(?:app.?key|application.?key)[:=]\s*["\'][a-zA-Z0-9]{32}["\']`), 1},
	{"New Relic License Key", regexp.MustCompile(`NRII-[a-f0-9]{32}`), 0},
	{"New Relic API Key", regexp.MustCompile(`(?i)new.?relic.{0,20}(?:license.?key|api.?key|admin.?api.?key)[:=]\s*["\'][a-zA-Z0-9_\-]+["\']`), 1},
	{"Grafana Token", regexp.MustCompile(`glc_[a-zA-Z0-9_\-]{40,}`), 0},
	{"Rollbar Token", regexp.MustCompile(`(?i)rollbar.{0,20}(?:access.?token|post.?server.?item.?access.?token)[:=]\s*["\'][a-zA-Z0-9]{32}["\']`), 1},
	{"Honeycomb API Key", regexp.MustCompile(`hcx[a-zA-Z0-9_\-]{30,}`), 0},
	{"Elastic APM Secret", regexp.MustCompile(`(?i)elastic.{0,20}apm.{0,20}(?:secret.?token|api.?key)[:=]\s*["\'][a-zA-Z0-9_\-]+["\']`), 1},

	// -- Realtime / Pub-Sub --
	{"Pusher Key", regexp.MustCompile(`(?i)(?:pusher|ably|pubnub).{0,20}(?:key|secret|token)[:=]\s*["\'][a-zA-Z0-9_\-]+["\']`), 1},
	{"Ably Key", regexp.MustCompile(`(?i)ably.{0,20}(?:api.?key|token)[:=]\s*["\'][a-zA-Z0-9_\-]+["\']`), 1},

	// -- CMS / Headless --
	{"Contentful Space ID", regexp.MustCompile(`(?i)contentful.{0,20}(?:space.?id|access.?token|delivery.?token)[:=]\s*["\'][a-zA-Z0-9_\-]+["\']`), 1},
	{"Sanity Token", regexp.MustCompile(`(?i)sanity.{0,20}(?:api.?key|token)[:=]\s*["\'][a-zA-Z0-9_\-]+["\']`), 1},
	{"Strapi Token", regexp.MustCompile(`(?i)strapi.{0,20}(?:api.?key|token)[:=]\s*["\'][a-zA-Z0-9_\-]+["\']`), 1},

	// -- General Secrets --
	{"Password Assignment", regexp.MustCompile(`(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*["\'][^"\'\s]{4,}["\']`), 1},
	{"Secret Assignment", regexp.MustCompile(`(?i)(?:secret|api[_-]?key|apikey)\s*[:=]\s*["\'][A-Za-z0-9\-_+=/]{8,}["\']`), 1},
	{"Token Assignment", regexp.MustCompile(`(?i)(?:token|auth|access[_-]?token)\s*[:=]\s*["\'][A-Za-z0-9\-_+=/]{8,}["\']`), 1},
	{"Generic High-Entropy", regexp.MustCompile(`["\'][A-Za-z0-9\-_+=/]{40,}["\']`), 1},
	{"Base64 in Code", regexp.MustCompile(`["\'][A-Za-z0-9+/]{40,}=*["\']`), 1},

	// -- Environment Variables --
	{"Env Variable", regexp.MustCompile(`process\.env\.(?:[A-Za-z_][A-Za-z0-9_]*)`), 0},
	{"Framework Env Prefix", regexp.MustCompile(`(?i)(?:VITE_|REACT_APP_|NEXT_PUBLIC_|NUXT_ENV_|SVELTE_APP_|GATSBY_|SANITY_STUDIO_|EXPO_PUBLIC_|PUBLIC_)[A-Z][A-Z0-9_]+`), 0},
	{"Database Env", regexp.MustCompile(`(?i)DATABASE_(?:URL|HOST|PORT|USER|PASSWORD|NAME)`), 0},
	{"Kubernetes Env", regexp.MustCompile(`(?i)KUBERNETES_SERVICE_(?:HOST|PORT)|KUBERNETES_NAMESPACE`), 0},
	{"AWS Env", regexp.MustCompile(`(?i)AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN|REGION|DEFAULT_REGION)`), 0},
	{"Redis Env", regexp.MustCompile(`(?i)REDIS(?:URL|_HOST|_PORT|_PASSWORD|_TLS_URL)`), 0},

	// -- URLs / IPs --
	{"Connection String", regexp.MustCompile(`(?i)(?:mongodb|mysql|postgres|postgresql|redis|rediss|amqp|rabbitmq)://[^\s"\'<>]+`), 0},
	{"Localhost URL", regexp.MustCompile(`https?://(?:localhost|127\.0\.0\.1)[^\s"\'<>]*`), 0},
	{"Internal IP", regexp.MustCompile(`(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})`), 0},
	{"Internal Domain", regexp.MustCompile(`https?://(?:intranet|internal|private|dev|staging|test|local)[^\s"\'<>]*`), 0},
	{"Hardcoded IP", regexp.MustCompile(`["\']\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}["\']`), 1},

	// -- Other --
	{"Telegram Bot Token", regexp.MustCompile(`[0-9]{8,10}:[A-Za-z0-9\-_]{35,}`), 0},
	{"Mapbox Token", regexp.MustCompile(`pk\.[a-zA-Z0-9]{60}\.[a-zA-Z0-9]{22}`), 0},
	{"Cloudinary URL", regexp.MustCompile(`cloudinary://[0-9]+:[A-Za-z0-9\-_]+@[a-zA-Z0-9\-_]+`), 0},
	{"Debug Endpoint", regexp.MustCompile(`["\']/[^"\']*(?:debug|dev|test|staging|sandbox)[^"\']*["\']`), 1},
	{"CORS Wildcard", regexp.MustCompile(`(?i)(?:cors|access.?control.?allow.?origin)[:=]\s*["\']\*["\']`), 1},
	{"Social Media Token", regexp.MustCompile(`(?:facebook|fb|twitter|instagram|linkedin).{0,10}(?:token|secret|key).{0,10}["\'][A-Za-z0-9\-_]+["\']`), 1},
	{"Analytics Key", regexp.MustCompile(`(?i)(?:segment|mixpanel|amplitude|heap|fullstory|hotjar).{0,20}(?:write.?key|api.?key|token|secret)[:=]\s*["\'][a-zA-Z0-9_\-]+["\']`), 1},

	// -- Inline JSON field patterns --
	{"Inline JSON: Token", regexp.MustCompile(`"token"\s*:\s*"[a-zA-Z0-9_\-+=/]{20,}"`), 0},
	{"Inline JSON: Password", regexp.MustCompile(`"password"\s*:\s*"[^"]{4,}"`), 0},
	{"Inline JSON: Secret", regexp.MustCompile(`"secret"\s*:\s*"[a-zA-Z0-9_\-+=/]{8,}"`), 0},
	{"Inline JSON: API Key", regexp.MustCompile(`"apiKey"\s*:\s*"[a-zA-Z0-9_\-+=/]{8,}"`), 0},
	{"Inline JSON: Access Token", regexp.MustCompile(`"accessToken"\s*:\s*"[a-zA-Z0-9_\-+=/]{8,}"`), 0},
	{"Inline JSON: Refresh Token", regexp.MustCompile(`"refreshToken"\s*:\s*"[a-zA-Z0-9_\-+=/]{8,}"`), 0},
}

func findSensitive(content string, sourceURL string) []SensitiveFinding {
	var findings []SensitiveFinding
	seen := make(map[string]bool)
	for _, sp := range sensitivePatterns {
		matches := sp.Pattern.FindAllString(content, -1)
		for _, match := range matches {
			trunc := match
			if len(trunc) > 60 {
				trunc = trunc[:57] + "..."
			}
			key := sp.Name + ":" + trunc
			if !seen[key] {
				seen[key] = true
				findings = append(findings, SensitiveFinding{
					Name:  sp.Name,
					Match: trunc,
				})
			}
		}
	}
	return findings
}

var commentPatterns = []*regexp.Regexp{
	regexp.MustCompile(`//\s*(TODO|FIXME|HACK|BUG|XXX|NOTE|OPTIMIZE|REVIEW|WORKAROUND|TEMP|HARDCODED|CREDENTIAL|PASSWORD|SECRET|APIKEY|TOKEN|SECURITY|VULNERABILITY|BACKDOOR|DEPRECATED|REMOVED|LEGACY|REFACTOR|CLEANUP|PERF|WARN|ERROR|HOTFIX|WORKAROUND|QUICKFIX|TEMPORARY|SHOULD.?FIX|NEEDS.?FIX|FIX.?LATER|KNOWN.?ISSUE|HERE.?BE.?DRAGONS)\b[^\n]*`),
	regexp.MustCompile(`/\*[\s\S]*?(TODO|FIXME|HACK|BUG|XXX|NOTE|OPTIMIZE|REVIEW|WORKAROUND|TEMP|HARDCODED|CREDENTIAL|PASSWORD|SECRET|APIKEY|TOKEN|SECURITY|VULNERABILITY|BACKDOOR|DEPRECATED|REMOVED|LEGACY|REFACTOR|CLEANUP|PERF|WARN|ERROR|HOTFIX|WORKAROUND|QUICKFIX|TEMPORARY|SHOULD.?FIX|NEEDS.?FIX|FIX.?LATER|KNOWN.?ISSUE|HERE.?BE.?DRAGONS)[\s\S]*?\*/`),
	regexp.MustCompile(`<!--[\s\S]*?(TODO|FIXME|HACK|BUG|NOTE|CREDENTIAL|PASSWORD|SECRET)[\s\S]*?-->`),
	regexp.MustCompile(`#\s*(TODO|FIXME|HACK|BUG|XXX|NOTE|CREDENTIAL|PASSWORD|SECRET)\b[^\n]*`),
	regexp.MustCompile(`//\s*https?://[^\s"']+`),
}

type CommentFinding struct {
	Comment string `json:"comment"`
	Type    string `json:"type"`
	Source  string `json:"source_url"`
}

func findComments(content string, sourceURL string) []CommentFinding {
	var findings []CommentFinding
	seen := make(map[string]bool)
	for _, re := range commentPatterns {
		matches := re.FindAllString(content, -1)
		for _, match := range matches {
			trunc := match
			if len(trunc) > 120 {
				trunc = trunc[:117] + "..."
			}
			if !seen[trunc] {
				seen[trunc] = true
				t := "Code Comment"
				if re.MatchString("//") {
					t = "Line Comment"
				} else if re.MatchString("/\\*") {
					t = "Block Comment"
				} else if re.MatchString("<!--") {
					t = "HTML Comment"
				}
				findings = append(findings, CommentFinding{
					Comment: trunc,
					Type:    t,
					Source:  sourceURL,
				})
			}
		}
	}
	return findings
}
