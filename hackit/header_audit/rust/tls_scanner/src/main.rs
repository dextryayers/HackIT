use openssl::asn1::Asn1Time;
use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};
use serde_json::{json, Value};
use std::env;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime};
use url::Url;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <url>", args[0]);
        std::process::exit(1);
    }

    let target = normalize_url(&args[1]);
    let parsed = match Url::parse(&target) {
        Ok(u) => u,
        Err(_) => {
            emit_json("error", json!({"message": "Invalid URL"}));
            return;
        }
    };

    let host = parsed.host_str().unwrap_or("").to_string();
    let port: u16 = parsed.port().unwrap_or(443);

    let best_result = connect_tls(&host, port);

    let mut findings: Vec<Value> = Vec::new();
    let mut tls_version = "Unknown".to_string();
    let mut cipher_suite = "Unknown".to_string();
    let mut cert_info = json!(null);

    if let Some(ref r) = best_result {
        tls_version = r.version.clone();
        cipher_suite = r.cipher.clone();
        cert_info = json!({
            "version": r.version, "cipher": r.cipher,
            "cert_subject": r.cert_subject, "cert_issuer": r.cert_issuer,
            "cert_expiry": r.cert_expiry, "days_left": r.cert_days_left,
            "self_signed": r.self_signed, "wildcard": r.wildcard,
        });

        if !r.tls12_ok && !r.tls13_ok {
            findings.push(tls_finding("critical", "No modern TLS",
                "Server does not support TLS 1.2 or 1.3",
                "Enable TLS 1.2 and 1.3, disable TLS 1.0/1.1"));
        }
        if r.tls13_ok {
            findings.push(tls_finding("info", "TLS 1.3 supported",
                "Server supports TLS 1.3 (modern, recommended)", ""));
        }

        let cipher_lower = r.cipher.to_lowercase();
        if cipher_lower.contains("rc4") || cipher_lower.contains("des") || cipher_lower.contains("3des") {
            findings.push(tls_finding("critical", "Weak cipher in use",
                &format!("Weak cipher: {}", r.cipher),
                "Disable RC4/DES/3DES ciphers"));
        }
        if cipher_lower.contains("cbc") && !cipher_lower.contains("gcm") && !cipher_lower.contains("chacha") {
            findings.push(tls_finding("medium", "CBC-mode cipher",
                &format!("CBC cipher: {} (Lucky13 attack risk)", r.cipher),
                "Prefer AEAD ciphers (GCM/ChaCha20)"));
        }

        if let Some(days) = r.cert_days_left {
            if days < 0 {
                findings.push(tls_finding("critical", "Certificate expired",
                    &format!("Certificate expired {} days ago", -days),
                    "Renew immediately"));
            } else if days < 14 {
                findings.push(tls_finding("high", "Certificate expiring soon",
                    &format!("Certificate expires in {} days", days),
                    "Renew within 14 days"));
            } else if days < 30 {
                findings.push(tls_finding("medium", "Certificate expiring",
                    &format!("Certificate expires in {} days", days),
                    "Plan renewal"));
            }
        }
        if r.self_signed {
            findings.push(tls_finding("medium", "Self-signed certificate",
                "Certificate is self-signed, not trusted by browsers",
                "Use a CA-trusted certificate"));
        }
        if r.wildcard {
            findings.push(tls_finding("low", "Wildcard certificate",
                &format!("Wildcard cert for {}", r.cert_subject),
                "Use specific hostname certs when possible"));
        }
    } else {
        findings.push(tls_finding("critical", "No TLS connection",
            "Unable to establish TLS connection",
            "Check if server supports TLS"));
    }

    emit_json("summary", json!({
        "target": target, "host": host, "port": port,
        "tls_version": tls_version, "cipher_suite": cipher_suite,
        "tls_1_3": best_result.as_ref().map_or(false, |r| r.tls13_ok),
        "has_tls": best_result.is_some(),
        "findings": findings.len(),
    }));

    if cert_info != json!(null) {
        emit_json("tls_detail", cert_info);
    }
    for f in &findings { emit_json("finding", f.clone()); }
    emit_json("tls_done", json!({"status": "ok"}));
}

struct TlsResult {
    version: String,
    cipher: String,
    cert_subject: String,
    cert_issuer: String,
    cert_expiry: String,
    cert_days_left: Option<i64>,
    self_signed: bool,
    wildcard: bool,
    tls12_ok: bool,
    tls13_ok: bool,
}

fn connect_tls(host: &str, port: u16) -> Option<TlsResult> {
    let addr_str = format!("{}:{}", host, port);

    let sock_addrs: Vec<_> = addr_str.to_socket_addrs().ok()?.collect();
    let addr = *sock_addrs.iter().find(|a| a.is_ipv4()).or_else(|| sock_addrs.first())?;

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    stream.set_write_timeout(Some(Duration::from_secs(10))).ok()?;

    let mut builder = SslConnector::builder(SslMethod::tls_client()).ok()?;
    builder.set_verify(SslVerifyMode::NONE);
    let tls_stream = builder.build().connect(host, stream).ok()?;

    let version = tls_version_name(&tls_stream);
    let cipher = tls_cipher_name(&tls_stream);
    let (subject, issuer, expiry, days_left, self_signed, wildcard) = extract_cert_info(&tls_stream);

    // Determine TLS 1.2 and 1.3 support via version string analysis
    let tls12_ok = version.contains("TLS 1.2");
    let tls13_ok = version.contains("TLS 1.3");

    Some(TlsResult {
        version, cipher,
        cert_subject: subject, cert_issuer: issuer,
        cert_expiry: expiry, cert_days_left: days_left,
        self_signed, wildcard,
        tls12_ok, tls13_ok,
    })
}

fn tls_version_name(stream: &SslStream<TcpStream>) -> String {
    match stream.ssl().version_str() {
        "TLSv1.3" => "TLS 1.3",
        "TLSv1.2" => "TLS 1.2",
        "TLSv1.1" => "TLS 1.1",
        "TLSv1" => "TLS 1.0",
        other => other,
    }
    .to_string()
}

fn tls_cipher_name(stream: &SslStream<TcpStream>) -> String {
    stream.ssl()
        .current_cipher()
        .map(|c| c.name().to_string())
        .unwrap_or_else(|| "Unknown".into())
}

fn extract_cert_info(stream: &SslStream<TcpStream>) -> (String, String, String, Option<i64>, bool, bool) {
    let default = ("Unknown".into(), "Unknown".into(), "Unknown".into(), None, false, false);

    let peer_cert = match stream.ssl().peer_certificate() {
        Some(c) => c,
        None => return default,
    };

    let subject = peer_cert.subject_name();
    let issuer = peer_cert.issuer_name();
    let subject_str = dn_string(subject);
    let issuer_str = dn_string(issuer);

    let not_after = peer_cert.not_after();
    let now_epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let now_asn1 = match Asn1Time::from_unix(now_epoch) {
        Ok(t) => t,
        Err(_) => return default,
    };
    let diff = match not_after.diff(&now_asn1) {
        Ok(d) => d,
        Err(_) => return default,
    };
    let days_left = Some(-(diff.days as i64));

    let expiry_str = format!("{}", not_after);
    let self_signed = subject_str == issuer_str;
    let wildcard = subject_str.contains("CN=*.");

    (subject_str, issuer_str, expiry_str, days_left, self_signed, wildcard)
}

fn dn_string(name: &openssl::x509::X509NameRef) -> String {
    name.entries()
        .map(|e| {
            format!(
                "{}={}",
                e.object(),
                e.data().to_string().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn normalize_url(s: &str) -> String {
    let s = s.trim();
    if s.starts_with("http://") || s.starts_with("https://") {
        s.to_string()
    } else {
        format!("https://{}", s)
    }
}

fn emit_json(t: &str, v: Value) {
    let mut obj = v.as_object().cloned().unwrap_or_default();
    obj.insert("type".to_string(), Value::String(t.to_string()));
    println!("{}", serde_json::to_string(&obj).unwrap_or_default());
}

fn tls_finding(sev: &str, category: &str, desc: &str, rec: &str) -> Value {
    json!({
        "finding_type": "tls", "category": category,
        "severity": sev, "description": desc, "recommendation": rec,
        "source": "tls_scanner"
    })
}
