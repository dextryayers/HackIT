mod ftp;
mod ssh;
mod telnet;
mod smtp;
mod pop3;
mod imap;
mod http;
mod mysql;
mod postgres;
mod redis;
mod ldap;
mod mssql;
mod mqtt;
mod vnc;
mod smb;
mod snmp;
mod rdp;

use std::collections::HashMap;
use std::sync::OnceLock;

fn proto_map() -> &'static HashMap<&'static str, u16> {
    static PORTS: OnceLock<HashMap<&'static str, u16>> = OnceLock::new();
    PORTS.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert("ftp", 21);
        m.insert("ssh", 22);
        m.insert("telnet", 23);
        m.insert("smtp", 25);
        m.insert("http", 80);
        m.insert("https", 443);
        m.insert("pop3", 110);
        m.insert("imap", 143);
        m.insert("ldap", 389);
        m.insert("mysql", 3306);
        m.insert("postgresql", 5432);
        m.insert("postgres", 5432);
        m.insert("redis", 6379);
        m.insert("mssql", 1433);
        m.insert("mqtt", 1883);
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

pub async fn try_auth(proto: &str, target: &str, port: u16, user: &str, pass: &str, to: u64) -> Result<bool, String> {
    match proto {
        "ftp" => ftp::auth(target, port, user, pass, to).await,
        "ssh" => ssh::auth(target, port, user, pass, to).await,
        "telnet" => telnet::auth(target, port, user, pass, to).await,
        "smtp" => smtp::auth(target, port, user, pass, to).await,
        "pop3" => pop3::auth(target, port, user, pass, to).await,
        "imap" => imap::auth(target, port, user, pass, to).await,
        "http" | "https" => http::auth(target, port, user, pass, to).await,
        "mysql" => mysql::auth(target, port, user, pass, to).await,
        "postgresql" | "postgres" => postgres::auth(target, port, user, pass, to).await,
        "redis" => redis::auth(target, port, user, pass, to).await,
        "ldap" | "ldaps" => ldap::auth(target, port, user, pass, to).await,
        "mssql" => mssql::auth(target, port, user, pass, to).await,
        "mqtt" => mqtt::auth(target, port, user, pass, to).await,
        "vnc" => vnc::auth(target, port, user, pass, to).await,
        "smb" => smb::auth(target, port, user, pass, to).await,
        "snmp" => snmp::auth(target, port, user, pass, to).await,
        "rdp" => rdp::auth(target, port, user, pass, to).await,
        _ => Err(format!("unsupported protocol: {}", proto)),
    }
}
