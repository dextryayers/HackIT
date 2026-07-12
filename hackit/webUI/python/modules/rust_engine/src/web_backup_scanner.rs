use crate::common::{ScanConfig, build_client};
use crate::common::WebBackupScanResult;
use std::time::Duration;
use tokio::task;

const BACKUP_PATTERNS: &[(&str, &str, &str)] = &[
    (".env", "Environment File", "critical"),
    (".env.bak", "Environment Backup", "critical"),
    (".env.old", "Environment Old", "critical"),
    (".env.local", "Local Environment", "critical"),
    (".git/config", "Git Config", "critical"),
    (".git/HEAD", "Git HEAD", "critical"),
    (".gitignore", "Git Ignore", "low"),
    (".htaccess", "Apache Config", "high"),
    (".htaccess.bak", "HTAccess Backup", "critical"),
    (".htpasswd", "HTPasswd", "critical"),
    ("wp-config.php.bak", "WP Config Backup", "critical"),
    ("wp-config.php.old", "WP Config Old", "critical"),
    ("wp-config.php~", "WP Config Tilde", "critical"),
    ("config.php.bak", "Config Backup", "critical"),
    ("config.php.old", "Config Old", "critical"),
    ("config.yml", "Config YAML", "high"),
    ("config.json", "Config JSON", "high"),
    ("database.sql", "Database SQL", "critical"),
    ("dump.sql", "Dump SQL", "critical"),
    ("backup.sql", "Backup SQL", "critical"),
    ("db_backup.sql", "DB Backup SQL", "critical"),
    (".DS_Store", "macOS Metadata", "low"),
    ("composer.lock", "Composer Lock", "low"),
    ("package-lock.json", "NPM Lock", "low"),
    ("Dockerfile", "Dockerfile", "medium"),
    ("docker-compose.yml", "Docker Compose", "medium"),
    ("Makefile", "Makefile", "low"),
    ("credentials.json", "Credentials JSON", "critical"),
    ("secrets.yml", "Secrets YAML", "critical"),
    ("id_rsa", "SSH Private Key", "critical"),
    ("private.key", "Private Key", "critical"),
    ("cert.pem", "Certificate PEM", "medium"),
    (".npmrc", "NPM Config", "medium"),
    (".netrc", "NetRC", "critical"),
    ("phpinfo.php", "PHP Info", "high"),
    ("info.php", "PHP Info", "high"),
    ("test.php", "Test Script", "medium"),
    ("adminer.php", "Adminer", "high"),
    ("pma.sql", "PHPMyAdmin SQL", "critical"),
];

const BASE_PATHS: &[&str] = &[
    "", "/admin", "/backup", "/wp-admin", "/wp-content",
    "/wp-includes", "/administrator", "/config", "/includes",
    "/private", "/secret", "/tmp", "/logs", "/data", "/db",
];

static EXTS: &[&str] = &[".bak", ".old", ".swp", "~"];

pub async fn scan(target: &str, _config: &ScanConfig) -> WebBackupScanResult {
    let client = build_client(15).unwrap_or_default();
    let domain = target.trim().to_lowercase();
    let base_url = format!("https://{}", domain);
    let timeout = Duration::from_secs(6);
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(25));
    let mut handles = Vec::new();

    for &(pattern, name, severity) in BACKUP_PATTERNS {
        for &base in BASE_PATHS {
            let url = format!("{}{}/{}", base_url, base, pattern);
            let client = client.clone();
            let sem = sem.clone();

            handles.push(task::spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                let start = std::time::Instant::now();
                let resp = client.get(&url).timeout(timeout).send().await.ok()?;
                let elapsed = start.elapsed().as_millis() as u64;
                let status = resp.status().as_u16();
                let size = resp.content_length().unwrap_or(0) as usize;
                Some(crate::common::BackupFileResult {
                    path: format!("{}/{}", base, pattern),
                    file_name: name.to_string(),
                    severity: severity.to_string(),
                    status,
                    size,
                    response_time_ms: elapsed,
                })
            }));
        }
    }

    for base in BASE_PATHS {
        for ext in EXTS {
            let url = format!("{}{}/index.php{}", base_url, base, ext);
            let client = client.clone();
            let sem = sem.clone();
            handles.push(task::spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                let resp = client.get(&url).timeout(timeout).send().await.ok()?;
                let status = resp.status().as_u16();
                let size = resp.content_length().unwrap_or(0) as usize;
                Some(crate::common::BackupFileResult {
                    path: format!("{}/index.php{}", base, ext),
                    file_name: format!("PHP File {}", ext),
                    severity: "medium".to_string(),
                    status, size,
                    response_time_ms: 0,
                })
            }));
        }
    }

    let mut found_files = Vec::new();
    for h in handles {
        if let Ok(Some(r)) = h.await {
            if r.status < 400 || r.status == 401 || r.status == 403 {
                found_files.push(r);
            }
        }
    }

    found_files.sort_by(|a, b| a.severity.cmp(&b.severity));

    WebBackupScanResult {
        domain,
        paths_checked: (BACKUP_PATTERNS.len() * BASE_PATHS.len()) + (BASE_PATHS.len() * EXTS.len()),
        files_found: found_files.len(),
        critical_files: found_files.iter().filter(|f| f.severity == "critical").count(),
        high_risk_files: found_files.iter().filter(|f| f.severity == "high").count(),
        files: found_files.into_iter().take(50).collect(),
    }
}
