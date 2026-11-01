//! TLS for implicit-TLS protocols (SMTPS, IMAPS, POP3S).
//!
//! Certificate validation is deliberately skipped: a mail server with a
//! self-signed certificate is still a mail server, and the question being asked
//! is "does this password work", not "is this certificate chained to a public
//! root". A brute forcer that refuses self-signed targets is useless in a lab.

use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio_rustls::TlsConnector;

/// Anything we can run a line protocol over, plain or wrapped.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

pub type BoxStream = Box<dyn AsyncStream>;

#[derive(Debug)]
struct AcceptAnyCertificate;

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

fn config() -> Arc<ClientConfig> {
    use std::sync::OnceLock;
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut config = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
                .with_no_client_auth();
            // Some legacy mail servers still cap out at TLS 1.2.
            config.enable_sni = true;
            Arc::new(config)
        })
        .clone()
}

/// Wrap a connected socket in TLS. `host` is used for SNI only.
pub async fn wrap(
    stream: TcpStream,
    host: &str,
    to: u64,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| format!("invalid TLS server name {}: {}", host, e))?;
    let connector = TlsConnector::from(config());
    tokio::time::timeout(Duration::from_secs(to), connector.connect(server_name, stream))
        .await
        .map_err(|_| "tls handshake timeout".to_string())?
        .map_err(|e| format!("tls: {}", e))
}

/// Open a TCP connection and, when `tls` is set, complete the handshake.
pub async fn connect(
    target: &str,
    port: u16,
    tls: bool,
    to: u64,
) -> Result<BoxStream, String> {
    let stream = tokio::time::timeout(
        Duration::from_secs(to),
        TcpStream::connect(format!("{}:{}", target, port)),
    )
    .await
    .map_err(|_| "connect timeout".to_string())?
    .map_err(|e| format!("connect: {}", e))?;
    let _ = stream.set_nodelay(true);

    if tls {
        let wrapped = wrap(stream, target, to).await?;
        Ok(Box::new(wrapped))
    } else {
        Ok(Box::new(stream))
    }
}
