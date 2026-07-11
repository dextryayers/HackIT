use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::{ClientConfig, ClientConnection, RootCertStore};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::common::*;
use crate::{progress, progress_done};

const IO_TIMEOUT: u64 = 10;

pub async fn scan(hostname: &str) -> SslTlsResult {
    progress!("ssl_tls", "running");
    let mut result = SslTlsResult {
        hostname: hostname.to_string(),
        ..Default::default()
    };

    let hostname = hostname.trim().to_lowercase();
    let addr = format!("{}:443", hostname);

    let stream = match timeout(Duration::from_secs(IO_TIMEOUT), TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            result.error = Some(format!("{:.80}", e));
            result.protocol = Some("none".into());
            progress_done!("ssl_tls");
            return result;
        }
        Err(_) => {
            result.error = Some("connection timed out".into());
            result.protocol = Some("none".into());
            progress_done!("ssl_tls");
            return result;
        }
    };

    let mut std_stream = match stream.into_std() {
        Ok(s) => s,
        Err(e) => {
            result.error = Some(format!("{:.80}", e));
            progress_done!("ssl_tls");
            return result;
        }
    };

    if let Err(e) = std_stream
        .set_read_timeout(Some(Duration::from_secs(IO_TIMEOUT)))
        .and_then(|_| std_stream.set_write_timeout(Some(Duration::from_secs(IO_TIMEOUT))))
    {
        result.error = Some(format!("{:.80}", e));
        progress_done!("ssl_tls");
        return result;
    }

    let host_clone = hostname.clone();

    let tls_outcome: Result<(Vec<Vec<u8>>, Option<String>, Option<String>), String> =
        tokio::task::spawn_blocking(move || {
            let root_store: RootCertStore =
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();

            let config = ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            let server_name =
                rustls::pki_types::ServerName::try_from(host_clone.as_str())
                    .map_err(|e| format!("invalid hostname: {}", e))?
                    .to_owned();

            let mut conn = ClientConnection::new(Arc::new(config), server_name)
                .map_err(|e| format!("tls init: {}", e))?;

            conn.complete_io(&mut std_stream)
                .map_err(|e| format!("handshake: {}", e))?;

            let certs: Vec<Vec<u8>> = conn
                .peer_certificates()
                .unwrap_or_default()
                .iter()
                .map(|c| c.to_vec())
                .collect();

            let cipher_suite = conn.negotiated_cipher_suite();

            let cipher_name = cipher_suite.map(|cs| format!("{:?}", cs.suite()));

            let version = cipher_name.as_deref().and_then(tls_version_from_cipher);

            Ok((certs, version, cipher_name))
        })
        .await
        .unwrap_or(Err("task panicked".into()));

    let (certs, tls_version, cipher_suite) = match tls_outcome {
        Ok(data) => data,
        Err(e) => {
            result.error = Some(format!("{:.80}", e));
            progress_done!("ssl_tls");
            return result;
        }
    };

    if let Some(cert_der) = certs.first() {
        result.chain_length = Some(certs.len() as u32);
        result.protocol = tls_version;
        result.cipher = cipher_suite;

        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        let fp = hex::encode(hasher.finalize());

        let parsed = parse_cert(cert_der);
        result.subject = parsed.subject;
        result.issuer = parsed.issuer;
        result.valid_from = parsed.valid_from;
        result.valid_to = parsed.valid_to;
        result.alt_names = parsed.sans;
        result.self_signed = parsed.self_signed;
        result.expired = parsed.expired;
        result.days_remaining = parsed.days_remaining;

        let grade = if parsed.sct_count > 0 {
            format!("SHA256:{}; SCT:{}", &fp[..16], parsed.sct_count)
        } else {
            format!("SHA256:{}; no SCT", &fp[..16])
        };
        result.grade = Some(grade);

        let tls_ver = result.protocol.as_deref().unwrap_or("");
        let cipher = result.cipher.as_deref().unwrap_or("");
        result.score = Some(security_score(
            tls_ver,
            cipher,
            !result.expired,
            san_covers(&result.alt_names, &hostname),
            !result.self_signed,
        ));
    }

    progress_done!("ssl_tls");
    result
}

fn tls_version_from_cipher(cipher: &str) -> Option<String> {
    if cipher.starts_with("TLS13_") || cipher.starts_with("TLS_1_3") {
        Some("TLS 1.3".into())
    } else if cipher.starts_with("TLS12_") || cipher.starts_with("TLS_1_2") || !cipher.is_empty() {
        Some("TLS 1.2".into())
    } else {
        None
    }
}

fn security_score(
    tls_ver: &str,
    cipher: &str,
    not_expired: bool,
    san_ok: bool,
    not_self_signed: bool,
) -> u32 {
    let mut s: u32 = 0;

    s += match tls_ver {
        "TLS 1.3" => 40,
        "TLS 1.2" => 30,
        "TLS 1.1" => 10,
        "TLS 1.0" => 0,
        _ => 0,
    };

    if cipher.contains("GCM") || cipher.contains("CHACHA20") || cipher.contains("CCM") {
        s += 20;
    }

    if not_expired {
        s += 20;
    }

    if san_ok {
        s += 10;
    }

    if not_self_signed {
        s += 10;
    }

    s
}

fn san_covers(sans: &[String], hostname: &str) -> bool {
    sans.iter().any(|san| san_match(san, hostname))
}

fn san_match(san: &str, hostname: &str) -> bool {
    if san == hostname {
        return true;
    }
    if let Some(domain) = san.strip_prefix("*.") {
        hostname.bytes().last() == Some(b'.')
            && hostname.len() > domain.len() + 1
            && hostname.ends_with(domain)
    } else {
        false
    }
}

// ── DER / X.509 certificate parser ────────────────────────────

struct DerSlice<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerSlice<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn read_tag(&mut self) -> Option<u8> {
        let t = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(t)
    }

    fn read_len(&mut self) -> Option<usize> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        if b & 0x80 == 0 {
            return Some(b as usize);
        }
        let n = (b & 0x7f) as usize;
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | *self.data.get(self.pos)? as usize;
            self.pos += 1;
        }
        Some(len)
    }

    fn read_tlv(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = self.read_tag()?;
        let len = self.read_len()?;
        if self.pos + len > self.data.len() {
            return None;
        }
        let val = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Some((tag, val))
    }
}

struct ParsedCert {
    subject: Option<String>,
    issuer: Option<String>,
    valid_from: Option<String>,
    valid_to: Option<String>,
    sans: Vec<String>,
    sct_count: u32,
    self_signed: bool,
    expired: bool,
    days_remaining: Option<i64>,
}

impl Default for ParsedCert {
    fn default() -> Self {
        Self {
            subject: None,
            issuer: None,
            valid_from: None,
            valid_to: None,
            sans: Vec::new(),
            sct_count: 0,
            self_signed: false,
            expired: false,
            days_remaining: None,
        }
    }
}

fn parse_cert(der: &[u8]) -> ParsedCert {
    let mut p = match DerSlice::new(der).read_tlv() {
        Some((0x30, body)) => DerSlice::new(body),
        _ => return ParsedCert::default(),
    };
    let tbs_der = match p.read_tlv() {
        Some((0x30, body)) => body,
        _ => return ParsedCert::default(),
    };

    let mut info = ParsedCert::default();
    let mut tbs = DerSlice::new(tbs_der);

    // version [0] EXPLICIT INTEGER – optional
    if tbs.peek_tag() == Some(0xA0) {
        let _ = tbs.read_tlv();
    }

    // serialNumber – INTEGER
    if tbs.peek_tag() == Some(0x02) {
        let _ = tbs.read_tlv();
    }

    // signature – SEQUENCE
    if tbs.peek_tag() == Some(0x30) {
        let _ = tbs.read_tlv();
    }

    // issuer – Name
    if let Some((0x30, name_der)) = tbs.read_tlv() {
        info.issuer = Some(parse_name(name_der));
    }

    // validity – SEQUENCE { Time, Time }
    if let Some((0x30, val_der)) = tbs.read_tlv() {
        let mut vp = DerSlice::new(val_der);
        info.valid_from = if !vp.is_empty() {
            parse_time_tlv(&mut vp)
        } else {
            None
        };
        info.valid_to = if !vp.is_empty() {
            parse_time_tlv(&mut vp)
        } else {
            None
        };

        if let Some(ref end) = info.valid_to {
            info.expired = time_is_past(end);
            info.days_remaining = days_until(end);
        }
    }

    // subject – Name
    if let Some((0x30, name_der)) = tbs.read_tlv() {
        info.subject = Some(parse_name(name_der));
    }

    // subjectPublicKeyInfo – SEQUENCE – skip
    if tbs.peek_tag() == Some(0x30) {
        let _ = tbs.read_tlv();
    }

    // issuerUniqueID [1] IMPLICIT – optional
    if tbs.peek_tag() == Some(0xA1) {
        let _ = tbs.read_tlv();
    }
    // subjectUniqueID [2] IMPLICIT – optional
    if tbs.peek_tag() == Some(0xA2) {
        let _ = tbs.read_tlv();
    }

    // extensions [3] EXPLICIT
    if tbs.peek_tag() == Some(0xA3) {
        if let Some((_, ext_outer)) = tbs.read_tlv() {
            let mut ep = DerSlice::new(ext_outer);
            while !ep.is_empty() {
                if let Some((0x30, ext_body)) = ep.read_tlv() {
                    let mut ex = DerSlice::new(ext_body);
                    if let Some((0x06, oid)) = ex.read_tlv() {
                        let oid_str = oid_to_string(oid);
                        // BOOLEAN critical – optional
                        if ex.peek_tag() == Some(0x01) {
                            let _ = ex.read_tlv();
                        }
                        if let Some((0x04, octet)) = ex.read_tlv() {
                            if oid_str == "2.5.29.17" {
                                info.sans = parse_san(octet);
                            } else if oid_str == "1.3.6.1.4.1.11129.2.4.2" {
                                // SCT extension present – count entries
                                let mut sc = DerSlice::new(octet);
                                let mut n = 0u32;
                                while sc.read_tlv().is_some() { n += 1; }
                                info.sct_count = n;
                            }
                        }
                    }
                } else {
                    break;
                }
            }
        }
    }

    if let (Some(ref subj), Some(ref iss)) = (&info.subject, &info.issuer) {
        info.self_signed = subj == iss;
    }

    info
}

fn parse_name(der: &[u8]) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut p = DerSlice::new(der);
    while !p.is_empty() {
        match p.read_tlv() {
            Some((0x31, set_body)) => {
                let mut sp = DerSlice::new(set_body);
                if let Some((0x30, seq_body)) = sp.read_tlv() {
                    let mut ip = DerSlice::new(seq_body);
                    if let Some((0x06, oid)) = ip.read_tlv() {
                        let oid_s = oid_to_string(oid);
                        let label = oid_label(&oid_s);
                        if let Some((_tag, val)) = ip.read_tlv() {
                            let s = string_from_asn1(val);
                            if !s.is_empty() {
                                parts.push(format!("{}={}", label, s));
                            }
                        }
                    }
                }
            }
            _ => break,
        }
    }
    parts.join(", ")
}

fn parse_time_tlv(p: &mut DerSlice) -> Option<String> {
    let (tag, raw) = p.read_tlv()?;
    let s = std::str::from_utf8(raw).ok()?.to_string();
    match tag {
                0x17 => {
                    let normalized = if s.len() >= 12 {
                        format!("20{}-{}-{}T{}:{}:{}Z",
                            &s[0..2], &s[2..4], &s[4..6], &s[6..8],
                            &s[8..10], &s[10..12])
                    } else {
                        s.clone()
                    };
                    Some(normalized)
                }
        0x18 => {
            if s.len() >= 15 {
                Some(format!("{}-{}-{}T{}:{}:{}Z",
                    &s[0..4], &s[4..6], &s[6..8],
                    &s[8..10], &s[10..12], &s[12..14]))
            } else {
                Some(s)
            }
        }
        _ => Some(s),
    }
}

fn time_is_past(time_str: &str) -> bool {
    if let Ok(dur) = parse_time(time_str) {
        dur <= SystemTime::now()
    } else {
        false
    }
}

fn days_until(time_str: &str) -> Option<i64> {
    let target = parse_time(time_str).ok()?;
    let now = SystemTime::now();
    if target > now {
        target.duration_since(now).ok().map(|d| (d.as_secs() / 86400) as i64)
    } else {
        Some(0)
    }
}

fn parse_time(s: &str) -> Result<SystemTime, ()> {
    let s = s.trim_end_matches('Z');
    if s.len() < 14 {
        return Err(());
    }
    let year: i64 = s[0..4].parse().map_err(|_| ())?;
    let month: u32 = s[5..7].parse().map_err(|_| ())?;
    let day: u32 = s[8..10].parse().map_err(|_| ())?;
    let hour: u32 = s[11..13].parse().map_err(|_| ())?;
    let min: u32 = s[14..16].parse().map_err(|_| ())?;
    let sec: u32 = if s.len() > 17 { s[17..19].parse().map_err(|_| ())? } else { 0 };

    let ts = chrono_timestamp(year, month, day, hour, min, sec)?;
    Ok(UNIX_EPOCH + Duration::from_secs(ts))
}

fn chrono_timestamp(
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    min: u32,
    sec: u32,
) -> Result<u64, ()> {
    if month < 1 || month > 12 || day < 1 || day > 31 {
        return Err(());
    }
    let days = days_before_year(year) + days_before_month(year, month) + (day as i64 - 1);
    let total_secs = days * 86400 + hour as i64 * 3600 + min as i64 * 60 + sec as i64;
    u64::try_from(total_secs).map_err(|_| ())
}

fn days_before_year(year: i64) -> i64 {
    let y = year - 1;
    y * 365 + y / 4 - y / 100 + y / 400
}

fn days_before_month(year: i64, month: u32) -> i64 {
    let base = match month {
        1 => 0,
        2 => 31,
        3 => 59,
        4 => 90,
        5 => 120,
        6 => 151,
        7 => 181,
        8 => 212,
        9 => 243,
        10 => 273,
        11 => 304,
        12 => 334,
        _ => 0,
    };
    if month > 2 && is_leap(year) { base + 1 } else { base }
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn parse_san(der: &[u8]) -> Vec<String> {
    let mut sans = Vec::new();
    let mut p = DerSlice::new(der);
    while !p.is_empty() {
        match p.read_tlv() {
            Some((0x82, val)) => {
                if let Ok(s) = std::str::from_utf8(val) {
                    sans.push(s.to_lowercase());
                }
            }
            Some((0x87, val)) => {
                if val.len() == 4 {
                    sans.push(format!("{}.{}.{}.{}", val[0], val[1], val[2], val[3]));
                } else if val.len() == 16 {
                    let hex: Vec<String> = val.chunks(2).map(|c| format!("{:02x}{:02x}", c[0], c[1])).collect();
                    sans.push(hex.join(":"));
                } else {
                    sans.push(format!("IP:{:?}", val));
                }
            }
            Some(_) => {}
            None => break,
        }
    }
    sans
}

fn oid_to_string(der: &[u8]) -> String {
    if der.is_empty() {
        return String::new();
    }
    let mut parts: Vec<String> = Vec::new();
    let first = der[0] as u16;
    parts.push(format!("{}", first / 40));
    parts.push(format!("{}", first % 40));
    let mut i = 1;
    while i < der.len() {
        let mut val: u64 = 0;
        while i < der.len() {
            let byte = der[i];
            val = (val << 7) | (byte & 0x7f) as u64;
            i += 1;
            if byte & 0x80 == 0 {
                break;
            }
        }
        parts.push(format!("{}", val));
    }
    parts.join(".")
}

fn oid_label(oid: &str) -> String {
    match oid {
        "2.5.4.3" => "CN".into(),
        "2.5.4.4" => "SN".into(),
        "2.5.4.5" => "serialNumber".into(),
        "2.5.4.6" => "C".into(),
        "2.5.4.7" => "L".into(),
        "2.5.4.8" => "ST".into(),
        "2.5.4.9" => "street".into(),
        "2.5.4.10" => "O".into(),
        "2.5.4.11" => "OU".into(),
        "2.5.4.12" => "title".into(),
        "2.5.4.13" => "description".into(),
        "2.5.4.17" => "postalCode".into(),
        "2.5.4.20" => "phone".into(),
        "2.5.4.41" => "name".into(),
        "2.5.4.42" => "givenName".into(),
        "2.5.4.43" => "initials".into(),
        "2.5.4.44" => "generationQualifier".into(),
        "2.5.4.45" => "uniqueIdentifier".into(),
        "2.5.4.46" => "dnQualifier".into(),
        "0.9.2342.19200300.100.1.1" => "uid".into(),
        "0.9.2342.19200300.100.1.25" => "dc".into(),
        "1.2.840.113549.1.9.1" => "emailAddress".into(),
        "1.3.6.1.4.1.311.60.2.1.3" => "jurisdictionOfIncorporationCountryName".into(),
        "1.3.6.1.4.1.311.60.2.1.2" => "jurisdictionOfIncorporationStateOrProvinceName".into(),
        "2.5.4.15" => "businessCategory".into(),
        "1.3.6.1.4.1.6449.1.2.1.3.1" => "domainIdentifier".into(),
        _ => oid.to_string(),
    }
}

fn string_from_asn1(raw: &[u8]) -> String {
    match std::str::from_utf8(raw) {
        Ok(s) => s.to_string(),
        Err(_) => {
            raw.iter()
                .map(|b| {
                    if b.is_ascii_graphic() || *b == b' ' {
                        char::from(*b).to_string()
                    } else {
                        "?".to_string()
                    }
                })
                .collect()
        }
    }
}
