mod ftp;
mod http;
mod imap;
mod ldap;
mod mqtt;
mod mssql;
mod mysql;
mod pop3;
mod postgres;
mod rdp;
mod redis;
mod smb;
mod smtp;
mod snmp;
mod ssh;
mod telnet;
mod vnc;

use std::collections::HashMap;
use std::sync::OnceLock;

/// The result of a single authentication attempt.
///
/// `Denied` is a definitive "the service rejected these credentials" and is
/// never retried. `Error` is "we could not complete the conversation" — a
/// refused socket, a TLS failure, a protocol mismatch — and the scheduler may
/// retry it. Collapsing the two is what makes naive brute forcers either
/// hammer a dead host or miss a valid login behind one dropped packet.
#[derive(Debug, Clone)]
pub enum AuthOutcome {
    Success,
    Denied,
    Error(String),
}

impl AuthOutcome {
    pub fn is_success(&self) -> bool {
        matches!(self, AuthOutcome::Success)
    }
}

/// Per-run knobs that some protocols need. Defaults are "the obvious thing",
/// so a bare `keystrike -P ssh -t host -u root -w toor` needs none of them.
#[derive(Debug, Clone, Default)]
pub struct ProtoOpts {
    /// HTTP request path, e.g. `/admin` or `/login.php`.
    pub http_path: String,
    /// `GET` or `POST`.
    pub http_method: String,
    /// Form body template; `^USER^` and `^PASS^` are substituted.
    pub http_body: String,
    /// Text that appears only on a failed login.
    pub http_fail: String,
    /// Text that appears only on a successful login.
    pub http_success: String,
    /// Extra `Name: value` headers.
    pub http_header: Vec<String>,
    /// Force `https` regardless of port.
    pub http_tls: bool,
    /// Send Basic credentials even when the path does not challenge.
    pub http_force_basic: bool,
    /// Bind address for protocols that need one (rare).
    pub source: String,
}

fn proto_map() -> &'static HashMap<&'static str, u16> {
    static PORTS: OnceLock<HashMap<&'static str, u16>> = OnceLock::new();
    PORTS.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert("ftp", 21);
        m.insert("ssh", 22);
        m.insert("telnet", 23);
        m.insert("smtp", 25);
        m.insert("smtps", 465);
        m.insert("http", 80);
        m.insert("https", 443);
        m.insert("pop3", 110);
        m.insert("pop3s", 995);
        m.insert("imap", 143);
        m.insert("imaps", 993);
        m.insert("ldap", 389);
        m.insert("ldaps", 636);
        m.insert("mysql", 3306);
        m.insert("postgresql", 5432);
        m.insert("postgres", 5432);
        m.insert("redis", 6379);
        m.insert("mssql", 1433);
        m.insert("mqtt", 1883);
        m.insert("mqtts", 8883);
        m.insert("vnc", 5900);
        m.insert("smb", 445);
        m.insert("snmp", 161);
        m.insert("rdp", 3389);
        m
    })
}

pub fn default_port(protocol: &str) -> u16 {
    proto_map().get(protocol).copied().unwrap_or(0)
}

pub fn supported_protocols() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = proto_map().keys().copied().collect();
    v.sort_unstable();
    v
}

/// Temporary bridge while the protocol modules still speak `Result<bool, String>`.
/// ST-2 replaces every body with a typed `AuthOutcome`; this classifier then
/// disappears.
fn classify(err: String) -> AuthOutcome {
    const DENIED: &[&str] = &[
        "auth", "login", "denied", "invalid", "incorrect", "failed", "failure",
        "rejected", "530", "535", "401", "403", "password", "credential",
        "unauthorized", "not authorized", "access denied", "no auth",
        "bad credentials", "authentication",
    ];
    let low = err.to_ascii_lowercase();
    if DENIED.iter().any(|k| low.contains(k)) {
        AuthOutcome::Denied
    } else {
        AuthOutcome::Error(err)
    }
}

pub async fn try_auth(
    proto: &str,
    target: &str,
    port: u16,
    user: &str,
    pass: &str,
    to: u64,
    opts: &ProtoOpts,
) -> AuthOutcome {
    let result = match proto {
        "ftp" => ftp::auth(target, port, user, pass, to).await,
        "ssh" => ssh::auth(target, port, user, pass, to).await,
        "telnet" => telnet::auth(target, port, user, pass, to).await,
        "smtp" | "smtps" => smtp::auth(target, port, user, pass, to).await,
        "pop3" | "pop3s" => pop3::auth(target, port, user, pass, to).await,
        "imap" | "imaps" => imap::auth(target, port, user, pass, to).await,
        "http" | "https" => http::auth(target, port, user, pass, to, opts).await,
        "mysql" => mysql::auth(target, port, user, pass, to).await,
        "postgresql" | "postgres" => postgres::auth(target, port, user, pass, to).await,
        "redis" => redis::auth(target, port, user, pass, to).await,
        "ldap" | "ldaps" => ldap::auth(target, port, user, pass, to).await,
        "mssql" => mssql::auth(target, port, user, pass, to).await,
        "mqtt" | "mqtts" => mqtt::auth(target, port, user, pass, to).await,
        "vnc" => vnc::auth(target, port, user, pass, to).await,
        "smb" => smb::auth(target, port, user, pass, to).await,
        "snmp" => snmp::auth(target, port, user, pass, to).await,
        "rdp" => rdp::auth(target, port, user, pass, to).await,
        other => return AuthOutcome::Error(format!("unsupported protocol: {}", other)),
    };

    match result {
        Ok(true) => AuthOutcome::Success,
        Ok(false) => AuthOutcome::Denied,
        Err(e) => classify(e),
    }
}
