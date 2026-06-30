package main

import "regexp"

type sensitivePattern struct {
	Name    string
	Pattern *regexp.Regexp
	Context int
}

var sensitivePatterns = []sensitivePattern{
	{"AWS Access Key ID", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), 0},
	{"AWS Secret Access Key", regexp.MustCompile(`(?i)aws.{0,20}["\'][0-9a-zA-Z\/+]{40}["\']`), 1},
	{"AWS Session Token", regexp.MustCompile(`(?i)aws.{0,30}(?:session.?token|security.?token)[:=]\s*["\'][A-Za-z0-9+/=]{40,}["\']`), 1},
	{"AWS AppSync Key", regexp.MustCompile(`da2-[a-zA-Z0-9]{26}`), 0},
	{"AWS S3 URL", regexp.MustCompile(`s3://[a-zA-Z0-9\-_]+`), 0},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), 0},
	{"Google OAuth Client ID", regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`), 0},
	{"GCP Service Account", regexp.MustCompile(`(?i)"type"\s*:\s*"service_account"`), 0},
	{"Azure Storage Key", regexp.MustCompile(`(?i)(?:azure|storage).{0,20}(?:account.?key|access.?key)[:=]\s*["\'][a-zA-Z0-9+/=]{86,88}["\']`), 1},
	{"Azure Connection String", regexp.MustCompile(`(?i)DefaultEndpointsProtocol=https;AccountName=[a-zA-Z0-9]+;AccountKey=[a-zA-Z0-9+/=]{86,88}`), 0},
	{"Alibaba Access Key", regexp.MustCompile(`LTAI[a-zA-Z0-9]{12,20}`), 0},
	{"DigitalOcean Token", regexp.MustCompile(`dop_v1_[a-zA-Z0-9_\-]{64}`), 0},
	{"OpenAI API Key", regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`), 0},
	{"Anthropic API Key", regexp.MustCompile(`sk-ant-[a-zA-Z0-9]{20,}`), 0},
	{"HuggingFace Token", regexp.MustCompile(`hf_[a-zA-Z0-9]{34,}`), 0},
	{"Replicate API Token", regexp.MustCompile(`r8_[a-zA-Z0-9_\-]{36,}`), 0},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z\-]{10,}`), 0},
	{"Slack Webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9+/]{44,46}`), 0},
	{"Discord Webhook", regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+`), 0},
	{"GitHub Token (new)", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`), 0},
	{"GitHub Fine-Grained PAT", regexp.MustCompile(`github_pat_[a-zA-Z0-9_]{22,}`), 0},
	{"GitLab Token", regexp.MustCompile(`glpat-[A-Za-z0-9\-_]{20,}`), 0},
	{"GitLab CI Job Token", regexp.MustCompile(`glcbt-[a-zA-Z0-9_\-]{20,}`), 0},
	{"Stripe Live Secret", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`), 0},
	{"Stripe Test Secret", regexp.MustCompile(`sk_test_[0-9a-zA-Z]{24,}`), 0},
	{"Stripe Webhook Secret", regexp.MustCompile(`whsec_[0-9a-zA-Z]{24,}`), 0},
	{"SendGrid API Key", regexp.MustCompile(`SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}`), 0},
	{"Mailgun API Key", regexp.MustCompile(`key-[a-f0-9]{32}`), 0},
	{"Twilio Account SID", regexp.MustCompile(`AC[a-f0-9]{32}`), 0},
	{"JWT Token", regexp.MustCompile(`eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+`), 0},
	{"Bearer Token", regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}`), 1},
	{"RSA Private Key", regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`), 0},
	{"EC Private Key", regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`), 0},
	{"OpenSSH Private Key", regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`), 0},
	{"PGP Private Key", regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`), 0},
	{"Generic Private Key", regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`), 0},
	{"MongoDB Connection", regexp.MustCompile(`mongodb(?:\+srv)?://[^\s"\'<>]+`), 0},
	{"PostgreSQL Connection", regexp.MustCompile(`postgres(?:ql)?(?:\+srv)?://[^\s"\'<>]+`), 0},
	{"MySQL Connection", regexp.MustCompile(`mysql(?:\+[a-z]+)?://[^\s"\'<>]+`), 0},
	{"Redis Connection", regexp.MustCompile(`redis(?:s|sentinel)?://[^\s"\'<>]+`), 0},
	{"RabbitMQ Connection", regexp.MustCompile(`amqps?://[^\s"\'<>]+`), 0},
	{"JDBC Connection", regexp.MustCompile(`jdbc:(?:mysql|postgresql|oracle|sqlserver|h2|sqlite)://[^\s"\'<>]+`), 0},
	{"npm Token", regexp.MustCompile(`npm_[A-Za-z0-9]{36,}`), 0},
	{"PyPI Token", regexp.MustCompile(`pypi-[a-zA-Z0-9_\-]{40,}`), 0},
	{"RubyGems Key", regexp.MustCompile(`rubygems_[a-f0-9]{48}`), 0},
	{"Docker Hub Token", regexp.MustCompile(`dcp_[a-zA-Z0-9_\-]{40,}`), 0},
	{"Sentry DSN", regexp.MustCompile(`https://[a-f0-9]{32}@[a-f0-9]{9,16}\.ingest\.sentry\.io`), 0},
	{"Datadog API Key", regexp.MustCompile(`datadog_api_key\s*[:=]\s*["\'][a-zA-Z0-9]{32}["\']`), 1},
	{"Grafana Token", regexp.MustCompile(`glc_[a-zA-Z0-9_\-]{40,}`), 0},
	{"Telegram Bot Token", regexp.MustCompile(`[0-9]{8,10}:[A-Za-z0-9\-_]{35,}`), 0},
	{"Mapbox Token", regexp.MustCompile(`pk\.[a-zA-Z0-9]{60}\.[a-zA-Z0-9]{22}`), 0},
	{"Cloudinary URL", regexp.MustCompile(`cloudinary://[0-9]+:[A-Za-z0-9\-_]+@[a-zA-Z0-9\-_]+`), 0},
	{"Supabase Anon Key", regexp.MustCompile(`(?i)supabase.{0,20}(?:anon.?key|service.?role.?key|url|project.?ref)[:=]\s*["\'][a-zA-Z0-9_\-]+["\']`), 1},
	{"Supabase JWT", regexp.MustCompile(`eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+`), 0},
	{"Firebase Database", regexp.MustCompile(`[a-zA-Z0-9\-_]+\.firebaseio\.com`), 0},
	{"Firebase App", regexp.MustCompile(`[a-zA-Z0-9\-_]+\.firebaseapp\.com`), 0},
	{"Password Assignment", regexp.MustCompile(`(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*["\'][^"\'\s]{4,}["\']`), 1},
	{"Secret Assignment", regexp.MustCompile(`(?i)(?:secret|api[_-]?key|apikey)\s*[:=]\s*["\'][A-Za-z0-9\-_+=/]{8,}["\']`), 1},
	{"Token Assignment", regexp.MustCompile(`(?i)(?:token|auth|access[_-]?token)\s*[:=]\s*["\'][A-Za-z0-9\-_+=/]{8,}["\']`), 1},
	{"Generic High-Entropy", regexp.MustCompile(`["\'][A-Za-z0-9\-_+=/]{40,}["\']`), 1},
	{"Base64 in Code", regexp.MustCompile(`["\'][A-Za-z0-9+/]{40,}=*["\']`), 1},
	{"Env Variable", regexp.MustCompile(`process\.env\.(?:[A-Za-z_][A-Za-z0-9_]*)`), 0},
	{"Framework Env Prefix", regexp.MustCompile(`(?i)(?:VITE_|REACT_APP_|NEXT_PUBLIC_|NUXT_ENV_|SVELTE_APP_|GATSBY_|SANITY_STUDIO_|EXPO_PUBLIC_|PUBLIC_)[A-Z][A-Z0-9_]+`), 0},
	{"Connection String", regexp.MustCompile(`(?i)(?:mongodb|mysql|postgres|postgresql|redis|rediss|amqp|rabbitmq)://[^\s"\'<>]+`), 0},
	{"Localhost URL", regexp.MustCompile(`https?://(?:localhost|127\.0\.0\.1)[^\s"\'<>]*`), 0},
	{"Internal IP", regexp.MustCompile(`(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})`), 0},
	{"CORS Wildcard", regexp.MustCompile(`(?i)(?:cors|access.?control.?allow.?origin)[:=]\s*["\']\*["\']`), 1},
	{"Inline JSON: Token", regexp.MustCompile(`"token"\s*:\s*"[a-zA-Z0-9_\-+=/]{20,}"`), 0},
	{"Inline JSON: Password", regexp.MustCompile(`"password"\s*:\s*"[^"]{4,}"`), 0},
	{"Inline JSON: Secret", regexp.MustCompile(`"secret"\s*:\s*"[a-zA-Z0-9_\-+=/]{8,}"`), 0},
	{"Inline JSON: API Key", regexp.MustCompile(`"apiKey"\s*:\s*"[a-zA-Z0-9_\-+=/]{8,}"`), 0},
	{"Inline JSON: Access Token", regexp.MustCompile(`"accessToken"\s*:\s*"[a-zA-Z0-9_\-+=/]{8,}"`), 0},
}

func findSensitive(content string, sourceURL string) []SensitiveFinding {
	var findings []SensitiveFinding
	seen := make(map[string]bool)
	for _, sp := range sensitivePatterns {
		matches := sp.Pattern.FindAllString(content, -1)
		for _, match := range matches {
			trunc := match
			if len(trunc) > 80 {
				trunc = trunc[:77] + "..."
			}
			key := sp.Name + ":" + trunc
			if !seen[key] {
				seen[key] = true
				findings = append(findings, SensitiveFinding{Name: sp.Name, Match: trunc})
			}
		}
	}
	return findings
}

var commentPatterns = []*regexp.Regexp{
	regexp.MustCompile(`//\s*(TODO|FIXME|HACK|BUG|XXX|NOTE|OPTIMIZE|REVIEW|WORKAROUND|TEMP|HARDCODED|CREDENTIAL|PASSWORD|SECRET|APIKEY|TOKEN|SECURITY|VULNERABILITY|BACKDOOR|DEPRECATED|LEGACY|REFACTOR|CLEANUP|PERF|WARN|ERROR|HOTFIX|SHOULD.?FIX|NEEDS.?FIX|FIX.?LATER|KNOWN.?ISSUE|HERE.?BE.?DRAGONS)\b[^\n]*`),
	regexp.MustCompile(`/\*[\s\S]*?(TODO|FIXME|HACK|BUG|XXX|NOTE|OPTIMIZE|REVIEW|WORKAROUND|TEMP|HARDCODED|CREDENTIAL|PASSWORD|SECRET|APIKEY|TOKEN|SECURITY|VULNERABILITY|BACKDOOR|DEPRECATED|LEGACY|REFACTOR|CLEANUP|PERF|WARN|ERROR|HOTFIX|SHOULD.?FIX|NEEDS.?FIX|FIX.?LATER|KNOWN.?ISSUE|HERE.?BE.?DRAGONS)[\s\S]*?\*/`),
	regexp.MustCompile(`<!--[\s\S]*?(TODO|FIXME|HACK|BUG|NOTE|CREDENTIAL|PASSWORD|SECRET)[\s\S]*?-->`),
	regexp.MustCompile(`#\s*(TODO|FIXME|HACK|BUG|XXX|NOTE|CREDENTIAL|PASSWORD|SECRET)\b[^\n]*`),
	regexp.MustCompile(`//\s*https?://[^\s"']+`),
}

func findComments(content string, sourceURL string) []CommentFinding {
	var findings []CommentFinding
	seen := make(map[string]bool)
	for _, re := range commentPatterns {
		matches := re.FindAllString(content, -1)
		for _, match := range matches {
			trunc := match
			if len(trunc) > 150 {
				trunc = trunc[:147] + "..."
			}
			if !seen[trunc] {
				seen[trunc] = true
				findings = append(findings, CommentFinding{Comment: trunc, Source: sourceURL})
			}
		}
	}
	return findings
}
