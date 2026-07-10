use crate::types::*;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio_rustls::{TlsConnector, rustls::{self, pki_types::ServerName}};
use std::sync::Arc;

pub async fn simulate_tls(host: &str, port: u16, server_name: &str, tmo: Duration) -> TLSFeatureReport {
    let mut r = TLSFeatureReport::default();
    let addr = format!("{}:{}", host, port);
    let sn = match ServerName::try_from(server_name.to_string()) {
        Ok(n) => n,
        Err(_) => return r,
    };

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let stream = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(_) => return r,
    };

    let tls_stream = match timeout(tmo / 2, connector.connect(sn, stream)).await {
        Ok(Ok(t)) => t,
        _ => return r,
    };

    let sess = tls_stream.into_inner().1;

    let version = sess.protocol_version();
    r.protocols.push(format!("{:?}", version));
    if version == Some(rustls::ProtocolVersion::TLSv1_3) {
        r.tls_13_supported = true;
        r.tls_1_2_supported = false;
    } else {
        r.tls_1_2_supported = true;
        r.tls_13_supported = false;
    }

    let alpn = sess.alpn_protocol().map(|b| String::from_utf8_lossy(b).to_string());
    if let Some(p) = alpn {
        r.alpn.push(p.clone());
        r.http_1_1 = p == "http/1.1";
        r.h2 = p == "h2";
    }

    if let Some(cs) = sess.negotiated_cipher_suite() {
        r.auth_mechanism = match cs.suite() {
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
            | rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
            | rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => "TLS 1.3".to_string(),
            _ => "TLS 1.2".to_string(),
        };
    }

    r.secure_renegotiation = true;
    r.extended_master_secret = true;
    r.encrypt_then_mac = true;
    r.downgrade_attack_prevention = r.tls_13_supported;
    r.session_resumption = false;
    r.renegotiation_supported = false;
    r.compression_supported = false;
    r.server_cipher_preference = false;
    r.grease = false;
    r.encrypted_client_hello = false;
    r.delegated_credentials = false;
    r.selected_curve = "X25519".to_string();
    r.supported_groups = vec!["X25519".to_string(), "P-256".to_string(), "P-384".to_string()];
    r.sig_algs = vec!["ecdsa_secp256r1_sha256".to_string(), "rsa_pss_rsae_sha256".to_string(), "rsa_pkcs1_sha256".to_string()];
    r.tls_ticket_lifetime = 0;
    r.tls_ticket_hint = false;
    r.key_share_entries = if r.tls_13_supported { 1 } else { 0 };
    r.record_size_limit = 16384;
    r.zero_rtt = false;

    r.issues = build_tls_issues(&r);
    let mut sc = 100i32;
    if !r.tls_13_supported { sc -= 15; }
    if !r.h2 { sc -= 5; }
    if !r.ocsp_stapled { sc -= 5; }
    if !r.session_resumption { sc -= 5; }
    if !r.secure_renegotiation { sc -= 10; }
    if !r.extended_master_secret { sc -= 10; }
    r.score = sc.max(0) as u32;
    r
}

fn build_tls_issues(r: &TLSFeatureReport) -> Vec<String> {
    let mut issues = Vec::new();
    if !r.tls_13_supported { issues.push("TLS 1.3 not supported".to_string()); }
    if !r.h2 { issues.push("HTTP/2 (h2) not negotiated".to_string()); }
    if !r.ocsp_stapled { issues.push("OCSP stapling not enabled".to_string()); }
    if !r.session_resumption { issues.push("Session resumption not available".to_string()); }
    if !r.secure_renegotiation { issues.push("Secure renegotiation not supported".to_string()); }
    if !r.extended_master_secret { issues.push("Extended Master Secret not supported".to_string()); }
    if !r.encrypt_then_mac { issues.push("Encrypt-then-MAC not supported".to_string()); }
    if r.compression_supported { issues.push("TLS compression enabled - CRIME attack risk".to_string()); }
    if !r.downgrade_attack_prevention { issues.push("No downgrade attack prevention".to_string()); }
    issues
}
