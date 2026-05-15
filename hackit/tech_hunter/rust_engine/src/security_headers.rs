use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct HeaderAudit {
    pub hsts_valid: bool,
    pub csp_present: bool,
    pub xfo_valid: bool,
    pub score: i32,
}

pub fn get_audit_json(headers_raw: &str) -> String {
    let headers_raw_lower = headers_raw.to_lowercase();
    
    let mut hsts_valid = headers_raw_lower.contains("strict-transport-security");
    let mut csp_present = headers_raw_lower.contains("content-security-policy");
    let mut xfo_valid = headers_raw_lower.contains("x-frame-options");
    let mut score = 0;

    if hsts_valid { score += 25; }
    if csp_present { score += 40; }
    if xfo_valid { score += 20; }
    if headers_raw_lower.contains("x-content-type-options") { score += 15; }

    let result = HeaderAudit { hsts_valid, csp_present, xfo_valid, score };
    serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string())
}
