use crate::types::*;
use crate::analyzer::{ConnData, TlsAnalysisResult};
use tokio::net::TcpStream;
use tokio::time::Duration;
use tokio_rustls::{TlsConnector, rustls::{self, pki_types::ServerName}};
use std::sync::Arc;
use x509_parser::prelude::*;
use sha2::{Sha256, Sha512, Digest};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hex;

pub async fn connect_and_fetch(host: &str, port: u16, tmo: Duration) -> Option<(TlsAnalysisResult, ConnData)> {
    let addr = format!("{}:{}", host, port);
    let server_name = ServerName::try_from(host.to_string()).ok()?;

    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let stream = TcpStream::connect(&addr).await.ok()?;
    let tls_stream = tokio::time::timeout(tmo, connector.connect(server_name, stream)).await.ok()?.ok()?;

    let (_, session) = tls_stream.into_inner();
    let peer_certs = session.peer_certificates()?;
    if peer_certs.is_empty() { return None; }

    let cert_der = peer_certs[0].to_vec();
    let chain_ders: Vec<Vec<u8>> = peer_certs.iter().map(|c| c.to_vec()).collect();

    let alpn = session.alpn_protocol().map(|b| String::from_utf8_lossy(b).to_string());
    let negotiated_cs = session.negotiated_cipher_suite().map(|cs| cs.suite());

    let cert_report = analyze_certificate(&cert_der, &chain_ders);
    let chain_report = analyze_chain(&chain_ders);

    let conn_data = ConnData {
        server_name: Some(host.to_string()),
        cert_der,
        chain_ders,
        negotiated_cipher_suite: negotiated_cs,
        alpn_protocol: alpn,
    };

    Some((TlsAnalysisResult { cert_report, chain_report }, conn_data))
}

pub fn analyze_certificate(cert_der: &[u8], chain: &[Vec<u8>]) -> CertReport {
    let mut r = CertReport::default();
    let cert = match parse_x509_certificate(cert_der) {
        Ok((_, c)) => c,
        Err(_) => { r.issues.push("Failed to parse certificate".to_string()); return r; }
    };

    r.subject_cn = cert.subject().iter_common_name().next()
        .and_then(|a| a.as_str().ok()).unwrap_or("").to_string();
    r.subject_org = cert.subject().iter_organization().next()
        .and_then(|a| a.as_str().ok()).unwrap_or("").to_string();
    r.subject_country = cert.subject().iter_country().next()
        .and_then(|a| a.as_str().ok()).unwrap_or("").to_string();
    r.issuer_cn = cert.issuer().iter_common_name().next()
        .and_then(|a| a.as_str().ok()).unwrap_or("").to_string();
    r.issuer_org = cert.issuer().iter_organization().next()
        .and_then(|a| a.as_str().ok()).unwrap_or("").to_string();
    r.issuer_country = cert.issuer().iter_country().next()
        .and_then(|a| a.as_str().ok()).unwrap_or("").to_string();

    r.not_before = format!("{:?}", cert.validity().not_before);
    r.not_after = format!("{:?}", cert.validity().not_after);

    let na_ts = cert.validity().not_after.to_datetime().unix_timestamp();
    let now_ts = ::time::OffsetDateTime::now_utc().unix_timestamp();
    let days = ((na_ts - now_ts) / 86400) as i32;
    r.days_remaining = days;
    r.expired = days < 0;
    r.expires_soon = !r.expired && days < 30;

    r.serial = cert.raw_serial_as_string();
    r.serial_bits = (cert.raw_serial().len() * 8) as u32;
    r.version = cert.version().0;

    r.sans = extract_sans(&cert);
    r.san_count = r.sans.len();
    r.wildcard = r.sans.iter().any(|s| s.starts_with('*'));
    r.subject_alt_names = extract_san_entries(&cert);

    let spki = cert.public_key();
    let oid_str = spki.algorithm.algorithm.to_id_string();
    if oid_str == "1.2.840.10045.2.1" || oid_str.starts_with("1.3.101.") {
        r.key_type = "EC".to_string();
        if let Ok(pk) = spki.parsed() {
            r.key_bits = pk.key_size() as u32 * 8;
        }
    } else if oid_str == "1.2.840.113549.1.1.1" {
        r.key_type = "RSA".to_string();
        if let Ok(pk) = spki.parsed() {
            r.key_bits = pk.key_size() as u32;
        }
    } else {
        r.key_type = format!("Unknown({})", oid_str);
    }

    r.key_strength = match r.key_bits {
        0 => "Unknown",
        b if b >= 4096 => "Very Strong",
        b if b >= 2048 => "Strong",
        b if b >= 1024 => "Weak",
        _ => "Insecure",
    }.to_string();

    r.sig_alg = cert.tbs_certificate.signature.algorithm.to_id_string();

    let mut h = Sha256::new();
    h.update(cert_der);
    r.fingerprint_sha256 = hex::encode(h.finalize()).to_uppercase();

    let mut h1 = Sha256::new();
    h1.update(&cert_der[..cert_der.len().min(16)]);
    r.fingerprint_sha1 = BASE64.encode(h1.finalize());

    let mut h512 = Sha512::new();
    h512.update(cert_der);
    r.fingerprint_sha512 = hex::encode(h512.finalize()).to_uppercase();

    r.self_signed = r.subject_cn == r.issuer_cn;
    r.chain_depth = chain.len();
    r.max_path_len = match cert.basic_constraints() {
        Ok(Some(bc)) => bc.value.path_len_constraint.map(|p| p as i32).unwrap_or(-1),
        _ => -1,
    };

    r.is_ca = cert.is_ca();

    let exts = cert.extensions();
    r.extensions_count = exts.len() as u32;

    parse_all_extensions(&mut r, exts);

    if let Some(ca) = chain.get(1) {
        if let Ok((_, ic)) = parse_x509_certificate(ca) {
            r.issuer_serial = ic.raw_serial_as_string();
        }
    }

    r.issues = build_cert_issues(&r);
    r
}

fn parse_all_extensions(r: &mut CertReport, exts: &[X509Extension]) {
    for ext in exts {
        let oid = ext.oid.to_id_string();
        if ext.critical {
            r.critical_extensions.push(oid.clone());
        }
        match ext.parsed_extension() {
            ParsedExtension::SCT(scts) => {
                r.sct_count = scts.len();
                r.sct_present = true;
            }
            ParsedExtension::CertificatePolicies(policies) => {
                r.is_ev = true;
                for p in policies.iter() {
                    r.cert_policy.push(p.policy_id.to_id_string());
                }
            }
            ParsedExtension::KeyUsage(ku) => {
                r.key_usage_critical = ext.critical;
                if ku.digital_signature() { r.key_usage.push("Digital Signature".to_string()); }
                if ku.non_repudiation() { r.key_usage.push("Non Repudiation".to_string()); }
                if ku.key_encipherment() { r.key_usage.push("Key Encipherment".to_string()); }
                if ku.data_encipherment() { r.key_usage.push("Data Encipherment".to_string()); }
                if ku.key_agreement() { r.key_usage.push("Key Agreement".to_string()); }
                if ku.key_cert_sign() { r.key_usage.push("Certificate Sign".to_string()); }
                if ku.crl_sign() { r.key_usage.push("CRL Sign".to_string()); }
                if ku.encipher_only() { r.key_usage.push("Encipher Only".to_string()); }
                if ku.decipher_only() { r.key_usage.push("Decipher Only".to_string()); }
            }
            ParsedExtension::ExtendedKeyUsage(eku) => {
                r.ext_key_usage_critical = ext.critical;
                if eku.server_auth { r.ext_key_usage.push("Server Auth".to_string()); r.cert_type.push("SSL Server".to_string()); }
                if eku.client_auth { r.ext_key_usage.push("Client Auth".to_string()); r.cert_type.push("SSL Client".to_string()); }
                if eku.code_signing { r.ext_key_usage.push("Code Signing".to_string()); }
                if eku.email_protection { r.ext_key_usage.push("Email Protection".to_string()); }
                if eku.time_stamping { r.ext_key_usage.push("Time Stamping".to_string()); r.tsa = true; }
                if eku.ocsp_signing { r.ext_key_usage.push("OCSP Signing".to_string()); }
                for o in eku.other.iter() {
                    r.ext_key_usage.push(o.to_id_string());
                }
            }
            ParsedExtension::BasicConstraints(bc) => {
                r.is_ca = bc.ca;
            }
            ParsedExtension::SubjectKeyIdentifier(kid) => {
                r.subject_key_id = hex::encode(kid.0);
            }
            ParsedExtension::AuthorityKeyIdentifier(aki) => {
                if let Some(kid) = &aki.key_identifier {
                    r.authority_key_id = hex::encode(kid.0);
                }
            }
            ParsedExtension::NameConstraints(_nc) => {
                r.name_constraints = "Present".to_string();
            }
            ParsedExtension::PolicyConstraints(_pc) => {
                r.policy_constraints = "Present".to_string();
            }
            ParsedExtension::InhibitAnyPolicy(iap) => {
                r.inhibit_any_policy = iap.skip_certs as i32;
            }
            _ => {}
        }
        if oid == "1.3.6.1.5.5.7.1.24" {
            r.ocsp_must_staple = true;
        }
        if oid == "1.3.6.1.5.5.7.1.11" {
            r.tls_feature_extensions.push("Signed Certificate Timestamps".to_string());
        }
        if oid == "1.3.6.1.5.5.7.1.25" {
            r.tls_feature_extensions.push("OCSP Must-Staple".to_string());
        }
    }

    let aia_ext = exts.iter().find(|e| e.oid.to_id_string() == "1.3.6.1.5.5.7.1.1");
    if let Some(aia) = aia_ext {
        if let ParsedExtension::AuthorityInfoAccess(aia_parsed) = aia.parsed_extension() {
            for desc in &aia_parsed.accessdescs {
                let m = desc.access_method.to_id_string();
                if m == "1.3.6.1.5.5.7.48.1" {
                    if let GeneralName::URI(u) = &desc.access_location {
                        r.ocsp_urls.push(u.to_string());
                        if r.ocsp_url.is_empty() {
                            r.ocsp_url = u.to_string();
                        }
                    }
                }
                if m == "1.3.6.1.5.5.7.48.2" {
                    if let GeneralName::URI(u) = &desc.access_location {
                        r.ca_issuer_urls.push(u.to_string());
                    }
                }
            }
        }
    }

    let cdp_ext = exts.iter().find(|e| e.oid.to_id_string() == "2.5.29.31");
    if let Some(cdp) = cdp_ext {
        if let ParsedExtension::CRLDistributionPoints(cdp_parsed) = cdp.parsed_extension() {
            for dp in cdp_parsed.iter() {
                if let Some(DistributionPointName::FullName(names)) = &dp.distribution_point {
                    for name in names {
                        if let GeneralName::URI(u) = name {
                            r.crl_dps.push(u.to_string());
                        }
                    }
                }
            }
        }
    }
}

fn extract_sans(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut sans = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(s) => sans.push(s.to_string()),
                GeneralName::IPAddress(ip) => sans.push(format_ip_bytes(ip)),
                _ => {}
            }
        }
    }
    sans
}

fn extract_san_entries(cert: &X509Certificate<'_>) -> Vec<SanEntry> {
    let mut entries = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            let (t, v) = match name {
                GeneralName::DNSName(s) => ("DNS".to_string(), s.to_string()),
                GeneralName::IPAddress(ip) => ("IP".to_string(), format_ip_bytes(ip)),
                GeneralName::RFC822Name(s) => ("Email".to_string(), s.to_string()),
                GeneralName::URI(u) => ("URI".to_string(), u.to_string()),
                GeneralName::DirectoryName(dn) => ("DirectoryName".to_string(), format!("{:?}", dn)),
                _ => ("Other".to_string(), format!("{:?}", name)),
            };
            entries.push(SanEntry { type_: t, value: v });
        }
    }
    entries
}

fn format_ip_bytes(bytes: &[u8]) -> String {
    if bytes.len() == 4 {
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    } else if bytes.len() == 16 {
        let segments: Vec<String> = bytes.chunks(2).map(|c| format!("{:02x}{:02x}", c[0], c[1])).collect();
        segments.join(":")
    } else {
        hex::encode(bytes)
    }
}

fn build_cert_issues(r: &CertReport) -> Vec<String> {
    let mut issues = Vec::new();
    if r.expired { issues.push(format!("Certificate expired {} days ago", -r.days_remaining)); }
    if r.expires_soon && !r.expired { issues.push(format!("Certificate expires in {} days", r.days_remaining)); }
    let sig_lower = r.sig_alg.to_lowercase();
    if sig_lower.contains("sha1") { issues.push(format!("Weak signature algorithm: {} (deprecated SHA-1)", r.sig_alg)); }
    if sig_lower.contains("md5") { issues.push(format!("Broken signature algorithm: {} (MD5 is compromised)", r.sig_alg)); }
    if r.key_strength == "Weak" || r.key_strength == "Insecure" {
        issues.push(format!("Weak public key: {}-bit {} ({})", r.key_bits, r.key_type, r.key_strength));
    }
    if r.self_signed { issues.push("Self-signed certificate (not trusted by browsers)".to_string()); }
    if r.wildcard { issues.push("Wildcard certificate (*.domain.com) - broader attack surface".to_string()); }
    if r.serial_bits < 64 { issues.push(format!("Short serial number ({} bits, should be >= 64)", r.serial_bits)); }
    if r.san_count == 0 { issues.push("No Subject Alternative Names (SANs)".to_string()); }
    if !r.sct_present { issues.push("No Signed Certificate Timestamps (SCT) - may not be recognized by some browsers".to_string()); }
    if r.is_ca { issues.push("Certificate is a CA certificate (should not be used for server auth)".to_string()); }
    issues
}

pub fn analyze_chain(chain: &[Vec<u8>]) -> ChainReport {
    let mut r = ChainReport::default();
    r.chain_depth = chain.len();
    r.intermediate_count = (chain.len().saturating_sub(2)) as u32;

    if let Some(leaf) = chain.first() {
        if let Ok((_, lc)) = parse_x509_certificate(leaf) {
            r.leaf_issuer = lc.issuer().iter_common_name().next()
                .and_then(|a| a.as_str().ok()).unwrap_or("").to_string();
            let exts = lc.extensions();
            let aia_ext = exts.iter().find(|e| e.oid.to_id_string() == "1.3.6.1.5.5.7.1.1");
            if let Some(aia) = aia_ext {
                if let ParsedExtension::AuthorityInfoAccess(aia_parsed) = aia.parsed_extension() {
                    for desc in &aia_parsed.accessdescs {
                        if desc.access_method.to_id_string() == "1.3.6.1.5.5.7.48.1" {
                            if let GeneralName::URI(u) = &desc.access_location {
                                r.ocsp_responders.push(u.to_string());
                            }
                        }
                    }
                }
            }
            let cdp_ext = exts.iter().find(|e| e.oid.to_id_string() == "2.5.29.31");
            if let Some(cdp) = cdp_ext {
                if let ParsedExtension::CRLDistributionPoints(cdp_parsed) = cdp.parsed_extension() {
                    for dp in cdp_parsed.iter() {
                        if let Some(DistributionPointName::FullName(names)) = &dp.distribution_point {
                            for name in names {
                                if let GeneralName::URI(u) = name {
                                    r.crl_urls.push(u.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if let Some(root_der) = chain.last() {
        if let Ok((_, rc)) = parse_x509_certificate(root_der) {
            r.root_ca = rc.subject().iter_common_name().next()
                .and_then(|a| a.as_str().ok()).unwrap_or("").to_string();
            r.root_org = rc.subject().iter_organization().next()
                .and_then(|a| a.as_str().ok()).unwrap_or("").to_string();
            r.root_ca_org = r.root_org.clone();
            r.root_ca_country = rc.subject().iter_country().next()
                .and_then(|a| a.as_str().ok()).unwrap_or("").to_string();
            r.root_serial = rc.raw_serial_as_string();
            let root_na_ts = rc.validity().not_after.to_datetime().unix_timestamp();
            let now_ts = ::time::OffsetDateTime::now_utc().unix_timestamp();
            let days = ((root_na_ts - now_ts) / 86400) as i32;
            r.root_expiry_days = days;
            r.root_expired = days < 0;

            let spki = rc.public_key();
            let oid_str = spki.algorithm.algorithm.to_id_string();
            if oid_str == "1.2.840.10045.2.1" || oid_str.starts_with("1.3.101.") {
                r.root_key_type = "EC".to_string();
                if let Ok(pk) = spki.parsed() {
                    r.root_key_bits = pk.key_size() as u32 * 8;
                }
            } else if oid_str == "1.2.840.113549.1.1.1" {
                r.root_key_type = "RSA".to_string();
                if let Ok(pk) = spki.parsed() {
                    r.root_key_bits = pk.key_size() as u32;
                }
            } else {
                r.root_key_type = format!("Unknown({})", oid_str);
            }

            let mut h = Sha256::new();
            h.update(root_der);
            r.root_fingerprint = hex::encode(h.finalize()).to_uppercase();
        }
    }

    for i in 1..chain.len().saturating_sub(1) {
        if let Ok((_, c)) = parse_x509_certificate(&chain[i]) {
            let cn = c.subject().iter_common_name().next()
                .and_then(|a| a.as_str().ok()).unwrap_or("").to_string();
            if !cn.is_empty() {
                r.intermediate_cns.push(cn.clone());
                let na_ts = c.validity().not_after.to_datetime().unix_timestamp();
                let now_ts = ::time::OffsetDateTime::now_utc().unix_timestamp();
                let exp_days = ((na_ts - now_ts) / 86400) as i32;
                let spki = c.public_key();
                let oid_s = spki.algorithm.algorithm.to_id_string();
                let (kt, kb) = if oid_s == "1.2.840.10045.2.1" {
                    ("EC".to_string(), spki.parsed().map(|pk| pk.key_size() as u32 * 8).unwrap_or(0))
                } else if oid_s == "1.2.840.113549.1.1.1" {
                    ("RSA".to_string(), spki.parsed().map(|pk| pk.key_size() as u32).unwrap_or(0))
                } else {
                    ("Unknown".to_string(), 0)
                };
                r.intermediate_details.push(IntermediateDetail {
                    cn,
                    org: c.subject().iter_organization().next()
                        .and_then(|a| a.as_str().ok()).unwrap_or("").to_string(),
                    expiry_days: exp_days,
                    sig_alg: c.tbs_certificate.signature.algorithm.to_id_string(),
                    key_type: kt,
                    key_bits: kb,
                });
            }
        }
    }

    r.issues = build_chain_issues(&r);
    r.score = calc_chain_score(&r);
    r
}

fn build_chain_issues(r: &ChainReport) -> Vec<String> {
    let mut issues = Vec::new();
    if r.root_expired { issues.push(format!("Root CA certificate expired {} days ago", -r.root_expiry_days)); }
    if r.root_expiry_days < 30 && !r.root_expired { issues.push(format!("Root CA expires in {} days", r.root_expiry_days)); }
    if r.intermediate_cns.is_empty() && r.chain_depth < 2 { issues.push("No intermediate certificates in chain".to_string()); }
    if r.ocsp_responders.is_empty() { issues.push("No OCSP responders configured".to_string()); }
    if r.crl_urls.is_empty() { issues.push("No CRL distribution points configured".to_string()); }
    if r.chain_depth < 2 { issues.push("Chain depth too shallow".to_string()); }
    issues
}

fn calc_chain_score(r: &ChainReport) -> u32 {
    let mut s = 100i32;
    if r.root_expired { return 0; }
    if r.root_expiry_days < 30 { s -= 20; }
    if r.intermediate_cns.is_empty() && r.chain_depth < 2 { s -= 15; }
    if r.ocsp_responders.is_empty() { s -= 10; }
    if r.crl_urls.is_empty() { s -= 5; }
    s.max(0) as u32
}
