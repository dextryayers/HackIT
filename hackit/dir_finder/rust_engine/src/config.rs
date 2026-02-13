use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DirResult {
    pub path: String,
    pub status: u16,
    pub size: u64,
    pub content_type: String,
    pub redirect: Option<String>,
    pub title: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScanConfig {
    // TARGET OPTIONS
    pub target: String,
    pub paths: Vec<String>,
    pub method: String,
    pub data: Option<String>,
    pub headers: HashMap<String, String>,
    pub cookie: Option<String>,
    pub auth: Option<String>, // user:pass
    pub proxy: Option<String>,
    pub user_agent: Option<String>,

    // PERFORMANCE OPTIONS
    pub threads: usize,
    pub timeout_ms: u64,
    pub delay_ms: u64,
    pub retries: usize,
    pub random_agent: bool,
    pub http2: bool,
    pub follow_redirects: bool,
    pub max_redirects: usize,

    // SCANNING OPTIONS
    pub extensions: Vec<String>,
    pub recursive: bool,
    pub depth: usize,
    pub exclude_status: Vec<u16>,
    pub include_status: Vec<u16>,
    pub exclude_length: Vec<u64>,
    pub include_length: Vec<u64>,

    // DETECTION OPTIONS
    pub detect_waf: bool,
    pub detect_tech: bool,
    pub detect_cms: bool,
    pub detect_backup: bool,
    pub smart_filter: bool,

    // ADVANCED OPTIONS
    pub fuzz_param: Option<String>,
    pub api_mode: bool,
    pub json_body: bool,
    pub graphql: bool,
    pub rate_limit: Option<u32>,

    // OSINT / SMART MODE
    pub auto_wordlist: bool,
    pub crawl: bool,
    pub extract_js: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ScanOutput {
    pub target: String,
    pub results: Vec<DirResult>,
    pub error: Option<String>,
    pub tech_stack: Option<Vec<String>>,
    pub waf_detected: Option<String>,
}
