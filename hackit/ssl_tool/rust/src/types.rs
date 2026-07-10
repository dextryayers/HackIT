use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CertReport {
    pub subject_cn: String,
    pub subject_org: String,
    pub subject_country: String,
    pub issuer_cn: String,
    pub issuer_org: String,
    pub issuer_country: String,
    pub not_before: String,
    pub not_after: String,
    pub days_remaining: i32,
    pub expired: bool,
    pub expires_soon: bool,
    pub key_type: String,
    pub key_bits: u32,
    pub key_strength: String,
    pub sig_alg: String,
    pub serial: String,
    pub serial_bits: u32,
    pub version: u32,
    pub sans: Vec<String>,
    pub san_count: usize,
    pub wildcard: bool,
    pub is_ca: bool,
    pub max_path_len: i32,
    pub chain_depth: usize,
    pub chain_valid: bool,
    pub self_signed: bool,
    pub sct_count: usize,
    pub sct_present: bool,
    pub is_ev: bool,
    pub ocsp_must_staple: bool,
    pub fingerprint_sha256: String,
    pub fingerprint_sha1: String,
    pub fingerprint_sha512: String,
    pub subject_key_id: String,
    pub authority_key_id: String,
    pub crl_dps: Vec<String>,
    pub ocsp_urls: Vec<String>,
    pub ca_issuer_urls: Vec<String>,
    pub key_usage: Vec<String>,
    pub key_usage_critical: bool,
    pub ext_key_usage: Vec<String>,
    pub ext_key_usage_critical: bool,
    pub cert_policy: Vec<String>,
    pub revoked: bool,
    pub issuer_serial: String,
    pub subject_alt_names: Vec<SanEntry>,
    pub extensions_count: u32,
    pub critical_extensions: Vec<String>,
    pub tls_feature_extensions: Vec<String>,
    pub name_constraints: String,
    pub policy_constraints: String,
    pub inhibit_any_policy: i32,
    pub cert_type: Vec<String>,
    pub tsa: bool,
    pub ocsp_url: String,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SanEntry {
    #[serde(rename = "type")]
    pub type_: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CipherInfo {
    pub id: u16,
    pub name: String,
    pub bits: u32,
    pub secure: bool,
    pub pfs: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CipherReport {
    pub supported: Vec<CipherInfo>,
    pub secure: Vec<CipherInfo>,
    pub weak: Vec<CipherInfo>,
    pub insecure: Vec<CipherInfo>,
    pub tls_13_only: Vec<CipherInfo>,
    pub pfs_enabled: bool,
    pub pfs_only: bool,
    pub best_cipher: String,
    pub worst_cipher: String,
    pub total_ciphers: usize,
    pub score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VulnFinding {
    pub name: String,
    pub severity: String,
    pub status: String,
    pub detail: String,
    pub cve: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VulnReport {
    pub findings: Vec<VulnFinding>,
    pub count: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub score: u32,
    pub beast: String,
    pub heartbleed: String,
    pub poodle_ssl: String,
    pub poodle_tls: String,
    pub freak: String,
    pub logjam: String,
    pub drown: String,
    pub sweet32: String,
    pub crime: String,
    pub breach: String,
    pub lucky13: String,
    pub rc4: String,
    pub robot: String,
    pub ticketbleed: String,
    pub bleichenbacher: String,
    pub cve_counts: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TLSFeatureReport {
    pub alpn: Vec<String>,
    pub h2: bool,
    pub http_1_1: bool,
    pub ocsp_stapled: bool,
    pub secure_renegotiation: bool,
    pub session_resumption: bool,
    pub zero_rtt: bool,
    pub tls_13_supported: bool,
    pub tls_1_2_supported: bool,
    pub tls_1_1_supported: bool,
    pub tls_1_0_supported: bool,
    pub ssl_3_supported: bool,
    pub ssl_2_supported: bool,
    pub protocols: Vec<String>,
    pub selected_curve: String,
    pub curve_id: u16,
    pub key_exchange: String,
    pub auth_mechanism: String,
    pub session_ticket_hint: u32,
    pub downgrade_attack_prevention: bool,
    pub extended_master_secret: bool,
    pub encrypt_then_mac: bool,
    pub renegotiation_supported: bool,
    pub renegotiation_secure: bool,
    pub compression_supported: bool,
    pub compression_methods: Vec<String>,
    pub tls_ticket_lifetime: u32,
    pub tls_ticket_hint: bool,
    pub key_share_entries: u32,
    pub server_cipher_preference: bool,
    pub record_size_limit: u32,
    pub delegated_credentials: bool,
    pub certificate_compression: Vec<String>,
    pub grease: bool,
    pub encrypted_client_hello: bool,
    pub supported_groups: Vec<String>,
    pub sig_algs: Vec<String>,
    pub ech_config: String,
    pub issues: Vec<String>,
    pub score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsRecord {
    pub name: String,
    pub value: String,
    pub ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DNSReport {
    pub a_records: Vec<String>,
    pub aaaa_records: Vec<String>,
    pub mx_records: Vec<String>,
    pub ns_servers: Vec<String>,
    pub soa_record: String,
    pub ptr_record: String,
    pub caa: String,
    pub spf: String,
    pub dkim_detect: bool,
    pub dmarc: String,
    pub dnssec: bool,
    pub txt_records: Vec<String>,
    pub cname_records: Vec<String>,
    pub ptr_records: Vec<String>,
    pub srv_records: Vec<String>,
    pub tlsa_records: Vec<String>,
    pub dkim_records: Vec<String>,
    pub spf_record_valid: bool,
    pub dmarc_record_valid: bool,
    pub caa_records: Vec<String>,
    pub reverse_dns: String,
    pub asn: u32,
    pub as_org: String,
    pub as_country: String,
    pub dnssec_valid: bool,
    pub dnssec_algorithms: Vec<String>,
    pub issues: Vec<String>,
    pub score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CookieInfo {
    pub name: String,
    pub value: String,
    pub secure: bool,
    pub httponly: bool,
    pub samesite: String,
    pub domain: String,
    pub path: String,
    pub max_age: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeaderInfo {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HTTPReport {
    pub status: u16,
    pub server: String,
    pub hsts: String,
    pub hsts_valid: bool,
    pub csp: String,
    pub x_frame_options: String,
    pub x_content_type: String,
    pub x_xss_protection: String,
    pub referrer_policy: String,
    pub permissions_policy: String,
    pub cookies_secure: bool,
    pub cookies_httponly: bool,
    pub cors_policy: String,
    pub location: String,
    pub content_type: String,
    pub content_length: u64,
    pub last_modified: String,
    pub x_permitted_cross_domain_policies: String,
    pub cross_origin_embedder_policy: String,
    pub cross_origin_opener_policy: String,
    pub cross_origin_resource_policy: String,
    pub access_control_allow_origin: String,
    pub access_control_allow_methods: String,
    pub strict_transport_security_max_age: u32,
    pub strict_transport_security_include_subdomains: bool,
    pub strict_transport_security_preload: bool,
    pub content_security_policy_directives: Vec<String>,
    pub set_cookie: Vec<CookieInfo>,
    pub headers_raw: Vec<HeaderInfo>,
    pub issues: Vec<String>,
    pub score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntermediateDetail {
    pub cn: String,
    pub org: String,
    pub expiry_days: i32,
    pub sig_alg: String,
    pub key_type: String,
    pub key_bits: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChainReport {
    pub chain_depth: usize,
    pub root_ca: String,
    pub root_org: String,
    pub root_ca_org: String,
    pub root_ca_country: String,
    pub root_serial: String,
    pub root_fingerprint: String,
    pub intermediate_cns: Vec<String>,
    pub root_expired: bool,
    pub root_expiry_days: i32,
    pub ocsp_responders: Vec<String>,
    pub crl_urls: Vec<String>,
    pub ocsp_responded: bool,
    pub chain_valid: bool,
    pub chain_trusted: bool,
    pub chain_revocation_checked: bool,
    pub intermediate_count: u32,
    pub leaf_issuer: String,
    pub ocsp_stapled: bool,
    pub ocsp_response_status: String,
    pub ocsp_produced_at: String,
    pub ocsp_next_update: String,
    pub crl_count: u32,
    pub crl_next_update: String,
    pub path_validation_depth: u32,
    pub root_key_type: String,
    pub root_key_bits: u32,
    pub intermediate_details: Vec<IntermediateDetail>,
    pub issues: Vec<String>,
    pub score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CryptoReport {
    pub ec_curves: Vec<String>,
    pub weak_curves: Vec<String>,
    pub key_exchange: String,
    pub forward_secrecy: bool,
    pub perfect_forward_secrecy: bool,
    pub ticket_key_rotation: bool,
    pub dh_params_bits: u32,
    pub dh_params_name: String,
    pub ecdhe_params_name: String,
    pub ecdhe_curve_id: u16,
    pub sig_alg_used: String,
    pub sig_hash_used: String,
    pub key_exchange_group: String,
    pub tls_13_key_exchange: String,
    pub kem_supported: bool,
    pub pqc_kyber: bool,
    pub ocsp_response_bits: u32,
    pub certificate_transparency: bool,
    pub prf_algorithm: String,
    pub issues: Vec<String>,
    pub score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PortInfo {
    pub port: u16,
    pub open: bool,
    pub service: String,
    pub tls: bool,
    pub banner: String,
    pub cert_cn: String,
    pub protocol: String,
    pub state: String,
    pub reason: String,
    pub ttl: u32,
    pub latency_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PortScanReport {
    pub target: String,
    pub open_ports: Vec<PortInfo>,
    pub total_open: usize,
    pub total_scanned: usize,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub grade: String,
    #[serde(default)]
    pub score: u32,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default)]
    pub all_issues: Vec<String>,
    #[serde(default)]
    pub recommendations: Vec<String>,
    #[serde(default)]
    pub certificate: CertReport,
    #[serde(default)]
    pub ciphers: CipherReport,
    #[serde(default)]
    pub vulnerabilities: VulnReport,
    #[serde(default)]
    pub tls_features: TLSFeatureReport,
    #[serde(default)]
    pub dns: DNSReport,
    #[serde(default)]
    pub http: HTTPReport,
    #[serde(default)]
    pub chain: ChainReport,
    #[serde(default)]
    pub crypto: CryptoReport,
    #[serde(default)]
    pub port_scan: PortScanReport,
    #[serde(default)]
    pub error: String,
}

impl ScanResult {
    pub fn new() -> Self {
        Self {
            host: String::new(),
            port: 0,
            grade: String::new(),
            score: 0,
            duration_ms: 0,
            all_issues: Vec::new(),
            recommendations: Vec::new(),
            certificate: CertReport::default(),
            ciphers: CipherReport::default(),
            vulnerabilities: VulnReport::default(),
            tls_features: TLSFeatureReport::default(),
            dns: DNSReport::default(),
            http: HTTPReport::default(),
            chain: ChainReport::default(),
            crypto: CryptoReport::default(),
            port_scan: PortScanReport::default(),
            error: String::new(),
        }
    }
}
