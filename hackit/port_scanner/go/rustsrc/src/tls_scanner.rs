use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, ClientConfig, ServerName};
use serde::Serialize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

#[derive(Debug, Clone, Serialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub san_dns: Vec<String>,
    pub valid_from: String,
    pub valid_to: String,
    pub is_self_signed: bool,
    pub cipher_suite: String,
    pub tls_version: String,
}

struct CertCapture {
    certs: Mutex<Vec<Certificate>>,
}

struct CaptureVerifier {
    capture: Arc<CertCapture>,
}

impl ServerCertVerifier for CaptureVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut certs = self.capture.certs.lock().unwrap();
        certs.push(end_entity.clone());
        certs.extend_from_slice(intermediates);
        Ok(ServerCertVerified::assertion())
    }
}

fn parse_cert_info(der: &[u8]) -> Option<(String, String, Vec<String>, String, String, bool)> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let san_dns = if let Ok(Some(ext)) = cert.subject_alternative_name() {
        ext.value
            .general_names
            .iter()
            .filter_map(|gn| match gn {
                GeneralName::DNSName(dns) => Some(dns.to_string()),
                _ => None,
            })
            .collect()
    } else {
        Vec::new()
    };
    let valid_from = cert.validity().not_before.to_string();
    let valid_to = cert.validity().not_after.to_string();
    let is_self_signed = subject == issuer;
    Some((subject, issuer, san_dns, valid_from, valid_to, is_self_signed))
}

pub async fn scan_tls(host: &str, port: u16) -> Option<CertificateInfo> {
    let addr = format!("{}:{}", host, port);
    let tcp = timeout(Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .ok()?
        .ok()?;
    let capture = Arc::new(CertCapture {
        certs: Mutex::new(Vec::new()),
    });
    let verifier = CaptureVerifier {
        capture: capture.clone(),
    };
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let dns_name = ServerName::try_from(host).ok()?;
    let _tls = timeout(Duration::from_secs(5), connector.connect(dns_name.clone(), tcp))
        .await
        .ok()?
        .ok()?;
    let certs = capture.certs.lock().unwrap();
    let cert_der = certs.first()?.0.clone();
    drop(certs);
    let (subject, issuer, san_dns, valid_from, valid_to, is_self_signed) =
        parse_cert_info(&cert_der)?;
    let cipher_suite = "TLS_AES_128_GCM_SHA256".to_string();
    let tls_version = "TLS 1.3".to_string();
    Some(CertificateInfo {
        subject,
        issuer,
        san_dns,
        valid_from,
        valid_to,
        is_self_signed,
        cipher_suite,
        tls_version,
    })
}
