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
	{"AWS Access Key ID",       regexp.MustCompile(`AKIA[0-9A-Z]{16}`), 0},
	{"AWS Secret Access Key",   regexp.MustCompile(`(?i)aws.{0,20}["\'][0-9a-zA-Z\/+]{40}["\']`), 1},
	{"Google API Key",          regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), 0},
	{"Google OAuth Client ID",  regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`), 0},
	{"Google OAuth Secret",     regexp.MustCompile(`["\'][0-9a-zA-Z\-_]{24}["\']`), 1},
	{"Slack Token",             regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z\-]{10,}`), 0},
	{"Slack Webhook",           regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9+/]{44,46}`), 0},
	{"Discord Webhook",         regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+`), 0},
	{"GitHub Token (new)",      regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`), 0},
	{"GitHub Token (old)",      regexp.MustCompile(`[0-9a-f]{40}`), 1},
	{"GitLab Token",            regexp.MustCompile(`glpat-[A-Za-z0-9\-_]{20,}`), 0},
	{"Stripe Live Secret",      regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`), 0},
	{"Stripe Test Secret",      regexp.MustCompile(`sk_test_[0-9a-zA-Z]{24,}`), 0},
	{"Stripe Public Key",       regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`), 0},
	{"Stripe Webhook Secret",   regexp.MustCompile(`whsec_[0-9a-zA-Z]{24,}`), 0},
	{"JWT Token",               regexp.MustCompile(`eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+`), 0},
	{"Bearer Token",            regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}`), 1},
	{"S3 Bucket",               regexp.MustCompile(`[a-zA-Z0-9\-_\.]+\.s3\.amazonaws\.com`), 0},
	{"S3 Bucket URL",           regexp.MustCompile(`s3://[a-zA-Z0-9\-_]+`), 0},
	{"Firebase Database",       regexp.MustCompile(`[a-zA-Z0-9\-_]+\.firebaseio\.com`), 0},
	{"Firebase App",            regexp.MustCompile(`[a-zA-Z0-9\-_]+\.firebaseapp\.com`), 0},
	{"RSA Private Key",         regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`), 0},
	{"EC Private Key",          regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`), 0},
	{"OpenSSH Private Key",     regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`), 0},
	{"PGP Private Key",         regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`), 0},
	{"Generic Private Key",     regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`), 0},
	{"DSA Private Key",         regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`), 0},
	{"Password Assignment",     regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\'\s]{4,}["\']`), 1},
	{"Secret Assignment",       regexp.MustCompile(`(?i)(?:secret|api[_-]?key|apikey)\s*[:=]\s*["\'][A-Za-z0-9\-_+=/]{8,}["\']`), 1},
	{"Token Assignment",        regexp.MustCompile(`(?i)(?:token|auth|access[_-]?token)\s*[:=]\s*["\'][A-Za-z0-9\-_+=/]{8,}["\']`), 1},
	{"Connection String",       regexp.MustCompile(`(?i)(?:mongodb|mysql|postgres|postgresql|redis|rediss|amqp|rabbitmq)://[^\s"\'<>]+`), 0},
	{"JDBC Connection",         regexp.MustCompile(`jdbc:(?:mysql|postgresql|oracle|sqlserver|h2|sqlite)://[^\s"\'<>]+`), 0},
	{"MongoDB Connection",      regexp.MustCompile(`mongodb(?:\+srv)?://[^\s"\'<>]+`), 0},
	{"Localhost URL",           regexp.MustCompile(`https?://(?:localhost|127\.0\.0\.1)[^\s"\'<>]*`), 0},
	{"Internal IP",             regexp.MustCompile(`(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})`), 0},
	{"Internal Domain",         regexp.MustCompile(`https?://(?:intranet|internal|private|dev|staging|test|local)[^\s"\'<>]*`), 0},
	{"Heroku API Key",          regexp.MustCompile(`[hH][eE][rR][oO][kK][uU].{0,20}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`), 1},
	{"npm Token",               regexp.MustCompile(`npm_[A-Za-z0-9]{36,}`), 0},
	{"NPM Token (old)",          regexp.MustCompile(`//registry\.npmjs\.org/:_authToken=[A-Za-z0-9\-_]+`), 0},
	{"Telegram Bot Token",      regexp.MustCompile(`[0-9]{8,10}:[A-Za-z0-9\-_]{35,}`), 0},
	{"Slack Bot Token",         regexp.MustCompile(`xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9\-_]{24}`), 0},
	{"Google Service Account",  regexp.MustCompile(`[a-zA-Z0-9\-_]+@[a-zA-Z0-9\-_]+\.iam\.gserviceaccount\.com`), 0},
	{"Sentry DSN",              regexp.MustCompile(`https://[a-f0-9]{32}@[a-f0-9]{9}\.ingest\.sentry\.io`), 0},
	{"Datadog API Key",         regexp.MustCompile(`datadog_api_key\s*[:=]\s*["\'][a-zA-Z0-9]{32}["\']`), 1},
	{"Mapbox Token",            regexp.MustCompile(`pk\.[a-zA-Z0-9]{60}\.[a-zA-Z0-9]{22}`), 0},
	{"Generic High-Entropy",    regexp.MustCompile(`["\'][A-Za-z0-9\-_+=/]{40,}["\']`), 1},
	{"Base64 in Code",          regexp.MustCompile(`["\'][A-Za-z0-9+/]{40,}=*["\']`), 1},
	{"Debug Endpoint",          regexp.MustCompile(`["\']/[^"\']*(?:debug|dev|test|staging|sandbox)[^"\']*["\']`), 1},
	{"Environment Variable",    regexp.MustCompile(`process\.env\.(?:[A-Za-z_][A-Za-z0-9_]*)`), 0},
	{"Hardcoded IP",            regexp.MustCompile(`["\']\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}["\']`), 1},
	{"Cloudinary URL",          regexp.MustCompile(`cloudinary://[0-9]+:[A-Za-z0-9\-_]+@[a-zA-Z0-9\-_]+`), 0},
	{"Social Media Token",      regexp.MustCompile(`(?:facebook|fb|twitter|instagram|linkedin).{0,10}(?:token|secret|key).{0,10}["\'][A-Za-z0-9\-_]+["\']`), 1},
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
	regexp.MustCompile(`//\s*(TODO|FIXME|HACK|BUG|XXX|NOTE|OPTIMIZE|REVIEW|WORKAROUND|TEMP|HARDCODED|CREDENTIAL|PASSWORD|SECRET|APIKEY|TOKEN)\b[^\n]*`),
	regexp.MustCompile(`/\*[\s\S]*?(TODO|FIXME|HACK|BUG|XXX|NOTE|OPTIMIZE|REVIEW|WORKAROUND|TEMP|HARDCODED|CREDENTIAL|PASSWORD|SECRET|APIKEY|TOKEN)[\s\S]*?\*/`),
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
