use serde::{Serialize, Deserialize};

// ── Structs ──

#[derive(Serialize, Deserialize)]
pub struct SubdomainResult { pub subdomain: String, pub resolution: Option<String>, pub source: String }

#[derive(Serialize, Deserialize)]
pub struct PortResult { pub port: u16, pub service: String, pub state: String }

#[derive(Serialize, Deserialize, Default)]
pub struct DnsResult { pub a: Vec<String>, pub aaaa: Vec<String>, pub mx: Vec<String>, pub ns: Vec<String>, pub txt: Vec<String>, pub cname: Vec<String>, pub soa: Option<String> }

#[derive(Serialize, Deserialize)]
pub struct WebtechResult { pub url: String, pub status: Option<u16>, pub server: Option<String>, pub tech: Vec<String>, pub headers: Vec<(String, String)> }

#[derive(Serialize, Deserialize)]
pub struct EmailResult { pub domain: String, pub patterns: Vec<String>, pub count: usize }

#[derive(Serialize, Deserialize)]
pub struct CrawlResult { pub url: String, pub title: Option<String>, pub links: Vec<String>, pub meta: Vec<(String, String)>, pub status: Option<u16> }

#[derive(Serialize, Deserialize)]
pub struct SensitiveResult { pub url: String, pub found: Vec<SensitiveFile> }

#[derive(Serialize, Deserialize)]
pub struct SensitiveFile { pub path: String, pub status: u16, pub size: Option<String> }

#[derive(Serialize, Deserialize)]
pub struct SecretResult { pub url: String, pub secrets: Vec<SecretFinding> }

#[derive(Serialize, Deserialize)]
pub struct SecretFinding { pub secret_type: String, pub value: String, pub location: String }

#[derive(Serialize, Deserialize)]
pub struct WafResult { pub url: String, pub waf: Option<String>, pub cdn: Option<String>, pub detected: bool, pub indicators: Vec<String> }

#[derive(Serialize, Deserialize)]
pub struct SocialResult { pub username: String, pub profiles: Vec<SocialProfile> }

#[derive(Serialize, Deserialize)]
pub struct SocialProfile { pub platform: String, pub url: String, pub exists: bool, pub status: Option<u16> }

#[derive(Serialize, Deserialize)]
pub struct CrtshResult { pub domain: String, pub certificates: Vec<CrtshEntry>, pub total: usize }

#[derive(Serialize, Deserialize)]
pub struct CrtshEntry { pub id: Option<i64>, pub issuer: Option<String>, pub issued: Option<String>, pub expired: Option<String>, pub sans: Vec<String> }

// ── Constants ──

pub const COMMON_PREFIXES: &[&str] = &[
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "vpn", "cdn",
    "blog", "app", "webmail", "remote", "portal", "ssh", "git", "jenkins",
    "jira", "smtp", "imap", "pop3", "autodiscover", "m", "mobile", "chat",
    "forum", "help", "support", "docs", "wiki", "status", "tracker",
    "monitor", "dashboard", "analytics", "metrics", "logs", "sync",
    "static", "assets", "media", "img", "upload", "download", "files",
    "backup", "cpanel", "whm", "server", "ns1", "ns2", "ns3", "ns4",
    "mx1", "mx2", "owa", "exchange", "gateway", "firewall", "proxy",
    "cache", "dns", "ldap", "radius", "test", "stage", "demo", "beta",
    "dev2", "prod", "production", "develop", "stg", "qa", "uat",
    "gitlab", "jenkins2", "ci", "cd", "deploy", "release", "build",
    "docker", "k8s", "kubernetes", "grafana", "prometheus", "kibana",
    "elastic", "logstash", "nagios", "zabbix", "puppet", "chef",
    "ansible", "terraform", "consul", "vault", "minio", "storage",
    "stream", "video", "audio", "cdn2", "origin", "edge", "waf",
    "redirect", "socket", "ws", "wss", "mqtt", "redis", "memcache",
    "mongo", "postgres", "mysql2", "oracle",
];

pub const TOP_PORTS: &[(u16, &str)] = &[
    (21,"FTP"),(22,"SSH"),(23,"Telnet"),(25,"SMTP"),(53,"DNS"),(80,"HTTP"),
    (110,"POP3"),(143,"IMAP"),(389,"LDAP"),(443,"HTTPS"),(445,"SMB"),(465,"SMTPS"),
    (587,"SMTP-Sub"),(993,"IMAPS"),(995,"POP3S"),(1433,"MSSQL"),(1521,"Oracle"),
    (2049,"NFS"),(3306,"MySQL"),(3389,"RDP"),(5432,"PostgreSQL"),(5900,"VNC"),
    (6379,"Redis"),(8080,"HTTP-Alt"),(8443,"HTTPS-Alt"),(9090,"HTTP-Alt2"),
    (27017,"MongoDB"),(11211,"Memcached"),(5000,"HTTP-Alt3"),(3000,"HTTP-Dev"),
    (9000,"HTTP-Alt4"),(9200,"Elasticsearch"),(9300,"ES-Transport"),(5601,"Kibana"),
    (15672,"RabbitMQ"),(5672,"AMQP"),(1883,"MQTT"),(8883,"MQTTS"),(4369,"Erlang-Port"),
    (25672,"Erlang-Dist"),(8000,"HTTP-Alt5"),(8888,"HTTP-Alt6"),(6000,"X11"),
    (4000,"HTTP-Alt7"),(5001,"HTTP-Alt8"),(9001,"HTTP-Alt9"),(2222,"SSH-Alt"),
    (4443,"HTTPS-Alt3"),(4444,"HTTP-Alt10"),(5555,"HTTP-Alt11"),(6666,"HTTP-Alt12"),
    (6667,"IRC"),(7000,"HTTP-Alt13"),(7001,"HTTP-Alt14"),(7070,"HTTP-Alt15"),
    (7777,"HTTP-Alt16"),(8001,"HTTP-Alt17"),(8008,"HTTP-Alt18"),(8081,"HTTP-Alt19"),
    (8082,"HTTP-Alt20"),(8090,"HTTP-Alt21"),(10000,"HTTP-Alt22"),
];

pub const SENSITIVE_PATHS: &[&str] = &[
    ".env", ".git/config", ".gitignore", ".htaccess", "admin/", "backup/",
    "wp-admin/", "wp-content/", "wp-includes/", "config/", "config.php",
    "configuration.php", "db/", "database/", "dump/", "sql/", "sql.gz",
    "backup.sql", "db.sql", "database.sql", ".sql", "robots.txt",
    "sitemap.xml", "crossdomain.xml", "phpinfo.php", "info.php",
    "test.php", "phpmyadmin/", "pma/", "adminer.php", "console/",
    "api/docs", "swagger.json", "openapi.json", "graphql",
    ".aws/credentials", ".npmrc", ".dockercfg", "Dockerfile",
    "docker-compose.yml", "Jenkinsfile", ".env.production",
    ".env.local", "credentials.json", "service-account.json",
    "composer.json", "package.json", "webpack.config.js",
    "rollup.config.js", "tsconfig.json", ".eslintrc",
    ".prettierrc", ".babelrc", "webpack.common.js",
    "vendor/", "node_modules/", ".idea/", ".vscode/",
    ".DS_Store", "Thumbs.db", "error.log", "access.log",
    "debug.log", "install/", "setup/", "upgrade/",
];

pub const PLATFORMS: &[(&str, &str)] = &[
    ("GitHub", "https://github.com/{}"),
    ("Twitter/X", "https://twitter.com/{}"),
    ("Instagram", "https://instagram.com/{}"),
    ("LinkedIn", "https://linkedin.com/in/{}"),
    ("Facebook", "https://facebook.com/{}"),
    ("YouTube", "https://youtube.com/@{}"),
    ("TikTok", "https://tiktok.com/@{}"),
    ("Reddit", "https://reddit.com/user/{}"),
    ("Pinterest", "https://pinterest.com/{}"),
    ("Medium", "https://medium.com/@{}"),
    ("Dev.to", "https://dev.to/{}"),
    ("Twitch", "https://twitch.tv/{}"),
    ("Telegram", "https://t.me/{}"),
    ("Discord", "https://discord.com/users/{}"),
    ("GitLab", "https://gitlab.com/{}"),
    ("BitBucket", "https://bitbucket.org/{}"),
    ("Keybase", "https://keybase.io/{}"),
    ("Mastodon", "https://mastodon.social/@{}"),
    ("WhatsApp", "https://wa.me/{}"),
    ("Snapchat", "https://snapchat.com/add/{}"),
    ("Flickr", "https://flickr.com/people/{}"),
    ("Tumblr", "https://tumblr.com/{}"),
    ("SoundCloud", "https://soundcloud.com/{}"),
    ("Spotify", "https://open.spotify.com/user/{}"),
    ("AngelList", "https://angel.co/{}"),
    ("ProductHunt", "https://producthunt.com/@{}"),
    ("HackerNews", "https://news.ycombinator.com/user?id={}"),
    ("StackOverflow", "https://stackoverflow.com/users/{}"),
    ("HackerOne", "https://hackerone.com/{}"),
    ("Bugcrowd", "https://bugcrowd.com/{}"),
    ("TryHackMe", "https://tryhackme.com/p/{}"),
    ("HackTheBox", "https://app.hackthebox.com/users/{}"),
];

pub const SECRET_PATTERNS: &[(&str, &str)] = &[
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key", r"(?i)aws(.{0,20})?(?-i)['][0-9a-zA-Z/+]{40}[']"),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("Slack Token", r"xox[abpors][0-9a-z\-]{10,}"),
    ("GitHub Token", r"ghp_[0-9a-zA-Z]{36}"),
    ("GitLab Token", r"glpat-[0-9a-zA-Z\-_]{20,}"),
    ("JWT Token", r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
    ("Private Key", r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ("Heroku API", r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"),
    ("Stripe Key", r"sk_live_[0-9a-zA-Z]{24,}"),
    ("Stripe Publishable", r"pk_live_[0-9a-zA-Z]{24,}"),
    ("Firebase URL", r"[a-z0-9-]+\.firebaseio\.com"),
    ("Twilio Key", r"SK[0-9a-fA-F]{32}"),
    ("Mailgun Key", r"key-[0-9a-zA-Z]{32}"),
    ("SendGrid Key", r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"),
    ("MongoDB URI", r"mongodb\+srv://[a-zA-Z0-9]+:[a-zA-Z0-9]+@"),
    ("PostgreSQL URI", r"postgres://[a-zA-Z0-9]+:[a-zA-Z0-9]+@"),
    ("MySQL URI", r"mysql://[a-zA-Z0-9]+:[a-zA-Z0-9]+@"),
    ("Redis URI", r"redis://[a-zA-Z0-9]+:[a-zA-Z0-9]+@"),
    ("SSH Key", r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("Generic API Key", r"(?i)(api_key|apikey|api_secret|access_key|secret_key|app_secret)[=:][0-9a-zA-Z_-]{16,64}"),
    ("Generic Password", r"(?i)(password|passwd|pwd)[=:][0-9a-zA-Z_-]{8,64}"),
    ("OAuth Token", r"(?i)(oauth_token|oauth_secret)[=:][0-9a-zA-Z_-]{10,}"),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
    ("Discord Webhook", r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+"),
    ("Google OAuth", r"[0-9]+-[0-9a-zA-Z_]{32}\.apps\.googleusercontent\.com"),
    ("Facebook OAuth", r"[0-9a-f]{32}"),
];

// ── Helper ──

pub fn build_client(timeout_secs: u64) -> Option<reqwest::Client> {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build().ok()
}
