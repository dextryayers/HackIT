use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct VulnEntry {
    pub cve_id: String,
    pub service_regex: String,
    pub version_range_start: String,
    pub version_range_end: String,
    pub severity: String,
    pub description: String,
}

fn parse_version(v: &str) -> Vec<u32> {
    let v = v.trim_start_matches('v').trim_start_matches('V');
    let mut parts: Vec<u32> = Vec::new();
    for segment in v.split(|c: char| !c.is_ascii_digit() && c != '.') {
        for num in segment.split('.') {
            if let Ok(n) = num.parse::<u32>() {
                parts.push(n);
            }
        }
    }
    if parts.is_empty() {
        parts.push(0);
    }
    parts
}

fn version_cmp(a: &[u32], b: &[u32]) -> std::cmp::Ordering {
    let max_len = a.len().max(b.len());
    for i in 0..max_len {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        match av.cmp(&bv) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

pub fn match_version(version: &str, range_start: &str, range_end: &str) -> bool {
    let v = parse_version(version);
    let start = parse_version(range_start);
    let end = parse_version(range_end);
    if range_start.is_empty() && range_end.is_empty() {
        return true;
    }
    if !range_start.is_empty() && version_cmp(&v, &start) == std::cmp::Ordering::Less {
        return false;
    }
    if !range_end.is_empty() && version_cmp(&v, &end) == std::cmp::Ordering::Greater {
        return false;
    }
    if !range_end.is_empty() && version_cmp(&v, &end) == std::cmp::Ordering::Equal {
        return true;
    }
    true
}

fn get_cve_db() -> Vec<VulnEntry> {
    vec![
        VulnEntry {
            cve_id: "CVE-2024-3094".into(),
            service_regex: "(?i)xz".into(),
            version_range_start: "5.6.0".into(),
            version_range_end: "5.6.1".into(),
            severity: "CRITICAL".into(),
            description: "XZ Utils backdoor (CVE-2024-3094) — SSH/remote code execution".into(),
        },
        VulnEntry {
            cve_id: "CVE-2023-48795".into(),
            service_regex: "(?i)openssh|libssh".into(),
            version_range_start: "1.0".into(),
            version_range_end: "9.6".into(),
            severity: "MEDIUM".into(),
            description: "Terrapin — SSH prefix truncation attack".into(),
        },
        VulnEntry {
            cve_id: "CVE-2023-28531".into(),
            service_regex: "(?i)openssh".into(),
            version_range_start: "3.0".into(),
            version_range_end: "9.3".into(),
            severity: "HIGH".into(),
            description: "OpenSSH — ssh-add agent forwarding vulnerability".into(),
        },
        VulnEntry {
            cve_id: "CVE-2023-38408".into(),
            service_regex: "(?i)openssh".into(),
            version_range_start: "8.9".into(),
            version_range_end: "9.3".into(),
            severity: "HIGH".into(),
            description: "OpenSSH — PKCS#11 provider remote code execution".into(),
        },
        VulnEntry {
            cve_id: "CVE-2023-25136".into(),
            service_regex: "(?i)openssh".into(),
            version_range_start: "2.0".into(),
            version_range_end: "9.1".into(),
            severity: "HIGH".into(),
            description: "OpenSSH — double-free in SSH key exchange".into(),
        },
        VulnEntry {
            cve_id: "CVE-2024-24786".into(),
            service_regex: "(?i)apache".into(),
            version_range_start: "0.1".into(),
            version_range_end: "2.4.58".into(),
            severity: "HIGH".into(),
            description: "Apache HTTP Server — HTTP/2 request splitting".into(),
        },
        VulnEntry {
            cve_id: "CVE-2023-31122".into(),
            service_regex: "(?i)apache".into(),
            version_range_start: "2.4.1".into(),
            version_range_end: "2.4.57".into(),
            severity: "MEDIUM".into(),
            description: "Apache HTTP Server — mod_macro buffer overflow".into(),
        },
        VulnEntry {
            cve_id: "CVE-2024-24989".into(),
            service_regex: "(?i)nginx".into(),
            version_range_start: "0.1".into(),
            version_range_end: "1.24.0".into(),
            severity: "MEDIUM".into(),
            description: "nginx — HTTP/2 memory leak / DoS".into(),
        },
        VulnEntry {
            cve_id: "CVE-2024-23915".into(),
            service_regex: "(?i)nginx".into(),
            version_range_start: "1.0".into(),
            version_range_end: "1.24.0".into(),
            severity: "HIGH".into(),
            description: "nginx — HTTP request smuggling vulnerability".into(),
        },
        VulnEntry {
            cve_id: "CVE-2023-44487".into(),
            service_regex: "(?i)nginx|apache|http".into(),
            version_range_start: "1.0".into(),
            version_range_end: "2.4.58".into(),
            severity: "HIGH".into(),
            description: "HTTP/2 Rapid Reset DoS attack".into(),
        },
        VulnEntry {
            cve_id: "CVE-2023-21971".into(),
            service_regex: "(?i)mysql|mariadb".into(),
            version_range_start: "5.0".into(),
            version_range_end: "8.0.32".into(),
            severity: "CRITICAL".into(),
            description: "MySQL Connector/J remote code execution".into(),
        },
        VulnEntry {
            cve_id: "CVE-2023-0361".into(),
            service_regex: "(?i)vsftpd".into(),
            version_range_start: "2.0".into(),
            version_range_end: "3.0.5".into(),
            severity: "HIGH".into(),
            description: "vsFTPd — denial of service / crash vulnerability".into(),
        },
        VulnEntry {
            cve_id: "CVE-2024-23651".into(),
            service_regex: "(?i)openssh".into(),
            version_range_start: "4.0".into(),
            version_range_end: "9.6".into(),
            severity: "HIGH".into(),
            description: "OpenSSH — signal handler race condition".into(),
        },
        VulnEntry {
            cve_id: "CVE-2020-15778".into(),
            service_regex: "(?i)openssh".into(),
            version_range_start: "1.0".into(),
            version_range_end: "8.4".into(),
            severity: "HIGH".into(),
            description: "OpenSSH — scp command injection".into(),
        },
        VulnEntry {
            cve_id: "CVE-2021-41617".into(),
            service_regex: "(?i)openssh".into(),
            version_range_start: "1.0".into(),
            version_range_end: "8.7".into(),
            severity: "MEDIUM".into(),
            description: "OpenSSH — privilege escalation via user enumeration".into(),
        },
        VulnEntry {
            cve_id: "CVE-2023-25584".into(),
            service_regex: "(?i)apache".into(),
            version_range_start: "2.4.0".into(),
            version_range_end: "2.4.55".into(),
            severity: "MEDIUM".into(),
            description: "Apache HTTP Server — mod_proxy out-of-bounds write".into(),
        },
        VulnEntry {
            cve_id: "CVE-2023-45871".into(),
            service_regex: "(?i)exim|smtp".into(),
            version_range_start: "1.0".into(),
            version_range_end: "4.97".into(),
            severity: "CRITICAL".into(),
            description: "Exim MTA — remote code execution (buffer overflow)".into(),
        },
        VulnEntry {
            cve_id: "CVE-2022-37434".into(),
            service_regex: "(?i)proftpd".into(),
            version_range_start: "1.0".into(),
            version_range_end: "1.3.8".into(),
            severity: "HIGH".into(),
            description: "ProFTPD — mod_sftp command injection".into(),
        },
        VulnEntry {
            cve_id: "CVE-2024-27316".into(),
            service_regex: "(?i)apache|http".into(),
            version_range_start: "2.4.0".into(),
            version_range_end: "2.4.59".into(),
            severity: "HIGH".into(),
            description: "Apache HTTP Server — HTTP/2 stream handling DoS".into(),
        },
        VulnEntry {
            cve_id: "CVE-2023-48795".into(),
            service_regex: "(?i)openssh|libssh|ssh".into(),
            version_range_start: "1.0".into(),
            version_range_end: "9.6".into(),
            severity: "MEDIUM".into(),
            description: "Terrapin attack — SSH channel integrity bypass".into(),
        },
        VulnEntry {
            cve_id: "CVE-2024-25680".into(),
            service_regex: "(?i)nginx".into(),
            version_range_start: "1.0".into(),
            version_range_end: "1.26.0".into(),
            severity: "MEDIUM".into(),
            description: "nginx — MP4 module out-of-bounds read".into(),
        },
        VulnEntry {
            cve_id: "CVE-2024-25053".into(),
            service_regex: "(?i)postgresql".into(),
            version_range_start: "12.0".into(),
            version_range_end: "16.2".into(),
            severity: "HIGH".into(),
            description: "PostgreSQL — JIT compilation buffer overflow".into(),
        },
    ]
}

pub fn check_vulnerabilities(service: &str, version: &str) -> Vec<VulnEntry> {
    let db = get_cve_db();
    let service_lower = service.to_lowercase();
    let mut matched = Vec::new();
    for entry in &db {
        if let Ok(re) = regex::Regex::new(&entry.service_regex) {
            if re.is_match(&service_lower) {
                if match_version(version, &entry.version_range_start, &entry.version_range_end) {
                    matched.push(entry.clone());
                }
            }
        }
    }
    matched
}
