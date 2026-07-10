use crate::types::*;
use tokio::net::TcpStream;
use tokio::time::Duration;
use tokio_rustls::{TlsConnector, rustls::{self, pki_types::ServerName}};
use std::sync::Arc;

pub async fn scan_ciphers(host: &str, port: u16, server_name: &str, _tmo: Duration) -> CipherReport {
    let mut report = CipherReport::default();
    let addr = format!("{}:{}", host, port);
    let sn = match ServerName::try_from(server_name.to_string()) {
        Ok(n) => n,
        Err(_) => return report,
    };

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let stream = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(_) => return report,
    };

    let tls_stream = match tokio::time::timeout(Duration::from_secs(5), connector.connect(sn, stream)).await {
        Ok(Ok(t)) => t,
        _ => return report,
    };

    let sess = tls_stream.into_inner().1;
    if let Some(cs) = sess.negotiated_cipher_suite() {
        let suite_id = cs.suite();
        let cs_name = format!("{:?}", suite_id);
        let id = u16::from(suite_id);
        let bits = if cs_name.contains("256") { 256 } else { 128 };
        let pfs = true;
        let secure = true;

        let cipher = CipherInfo {
            id,
            name: cs_name.clone(),
            bits,
            secure,
            pfs,
            reason: String::new(),
        };
        report.supported.push(cipher.clone());
        report.secure.push(cipher);
        report.best_cipher = cs_name;
        report.total_ciphers = 1;
        report.pfs_enabled = true;
        report.pfs_only = true;
        report.score = 100;
    }

    report
}
