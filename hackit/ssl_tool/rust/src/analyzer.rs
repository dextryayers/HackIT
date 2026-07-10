use crate::types::*;
use tokio::time::{timeout, Duration};
use tokio_rustls::rustls;

pub fn analyze(host: &str, port: u16, timeout_secs: u16, _full: bool) -> ScanResult {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async { analyze_async(host, port, timeout_secs).await })
}

async fn analyze_async(host: &str, port: u16, timeout_secs: u16) -> ScanResult {
    let overall_timeout = Duration::from_secs(timeout_secs as u64 + 10);
    match timeout(overall_timeout, do_analyze(host, port, timeout_secs)).await {
        Ok(r) => r,
        Err(_) => {
            let mut r = ScanResult::new();
            r.host = host.to_string();
            r.port = port;
            r.error = "Scan timed out".to_string();
            r
        }
    }
}

async fn do_analyze(host: &str, port: u16, timeout_secs: u16) -> ScanResult {
    let mut result = ScanResult::new();
    result.host = host.to_string();
    result.port = port;

    let tls_timeout = Duration::from_secs((timeout_secs as f64 * 0.3) as u64).max(Duration::from_secs(5));

    let (tls_analysis, conn_data) = match crate::cert::connect_and_fetch(host, port, tls_timeout).await {
        Some(data) => data,
        None => {
            result.error = format!("Failed to connect to {}:{}", host, port);
            return result;
        }
    };

    result.certificate = tls_analysis.cert_report.clone();
    result.chain = tls_analysis.chain_report.clone();

    let sn = conn_data.server_name.as_deref().unwrap_or(host);
    let rem_timeout = Duration::from_secs((timeout_secs as f64 * 0.6) as u64).max(Duration::from_secs(8));

    let (cipher_res, vuln_res, tls_res, crypto_res) = tokio::join!(
        crate::cipher::scan_ciphers(host, port, sn, rem_timeout),
        crate::vuln::scan_vulnerabilities(host, port, sn, rem_timeout),
        crate::tls_sim::simulate_tls(host, port, sn, rem_timeout),
        crate::crypto::scan_crypto(host, port, sn, rem_timeout),
    );

    result.ciphers = cipher_res;
    result.vulnerabilities = vuln_res;
    result.tls_features = tls_res;
    result.crypto = crypto_res;

    let light_timeout = Duration::from_secs((timeout_secs as f64 * 0.2) as u64).max(Duration::from_secs(4));

    let (dns_res, http_res, port_res) = tokio::join!(
        crate::dns::dns_lookup(host),
        crate::http::http_check(host, port, light_timeout),
        crate::port::scan_port(host, port, light_timeout),
    );

    result.dns = dns_res;
    result.http = http_res;
    result.port_scan = port_res;

    let score = crate::report::calculate_final_grade(&result);
    result.score = score;
    result.grade = crate::report::calculate_grade(score);

    let all_issues = crate::report::collect_all_issues(&result);
    result.all_issues = all_issues;
    result.recommendations = crate::report::generate_recommendations(&result);

    result
}

#[allow(dead_code)]
pub struct ConnData {
    pub server_name: Option<String>,
    pub cert_der: Vec<u8>,
    pub chain_ders: Vec<Vec<u8>>,
    pub negotiated_cipher_suite: Option<rustls::CipherSuite>,
    pub alpn_protocol: Option<String>,
}

#[derive(Clone)]
pub struct TlsAnalysisResult {
    pub cert_report: CertReport,
    pub chain_report: ChainReport,
}
