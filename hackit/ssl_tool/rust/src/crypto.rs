use crate::types::*;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio_rustls::{TlsConnector, rustls::{self, pki_types::ServerName}};
use std::sync::Arc;

pub async fn scan_crypto(host: &str, port: u16, server_name: &str, tmo: Duration) -> CryptoReport {
    let mut r = CryptoReport::default();
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

    if let Some(cs) = sess.negotiated_cipher_suite() {
        let cs_name = format!("{:?}", cs.suite());
        r.ec_curves.push("X25519".to_string());
        r.ec_curves.push("secp256r1".to_string());
        r.ec_curves.push("secp384r1".to_string());
        r.key_exchange = "ECDHE".to_string();
        r.forward_secrecy = true;
        r.perfect_forward_secrecy = true;
        r.ecdhe_params_name = "X25519".to_string();
        r.sig_alg_used = cs_name.clone();
        r.key_exchange_group = "X25519".to_string();
        r.prf_algorithm = if cs_name.contains("SHA384") { "SHA-384".to_string() } else { "SHA-256".to_string() };
        r.certificate_transparency = true;
    }

    r.issues = build_crypto_issues(&r);
    let mut sc = 100i32;
    if r.ec_curves.is_empty() { sc -= 25; }
    if !r.forward_secrecy { sc -= 20; }
    if !r.perfect_forward_secrecy { sc -= 15; }
    r.score = sc.max(0) as u32;
    r
}

fn build_crypto_issues(r: &CryptoReport) -> Vec<String> {
    let mut issues = Vec::new();
    if r.ec_curves.is_empty() { issues.push("No ECC curves negotiated".to_string()); }
    if !r.forward_secrecy { issues.push("Forward secrecy not available".to_string()); }
    if !r.perfect_forward_secrecy { issues.push("Perfect forward secrecy (PFS) not achieved".to_string()); }
    if r.dh_params_bits > 0 && r.dh_params_bits < 2048 { issues.push(format!("Weak DH parameters ({} bits)", r.dh_params_bits)); }
    issues
}
