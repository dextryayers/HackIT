use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HeaderSecurity {
    pub hsts: bool,
    pub csp: bool,
    pub x_frame_options: Option<String>,
    pub x_xss_protection: Option<String>,
    pub x_content_type_options: bool,
    pub referrer_policy: Option<String>,
    pub permissions_policy: bool,
    pub server_header: Option<String>,
    pub powered_by: Option<String>,
}

pub fn analyze_headers(headers: &HashMap<String, String>) -> HeaderSecurity {
    let mut sec = HeaderSecurity::default();
    
    for (k, v) in headers {
        let key = k.to_lowercase();
        match key.as_str() {
            "strict-transport-security" => sec.hsts = true,
            "content-security-policy" => sec.csp = true,
            "x-frame-options" => sec.x_frame_options = Some(v.clone()),
            "x-xss-protection" => sec.x_xss_protection = Some(v.clone()),
            "x-content-type-options" => sec.x_content_type_options = v.to_lowercase().contains("nosniff"),
            "referrer-policy" => sec.referrer_policy = Some(v.clone()),
            "permissions-policy" => sec.permissions_policy = true,
            "server" => sec.server_header = Some(v.clone()),
            "x-powered-by" => sec.powered_by = Some(v.clone()),
            _ => {}
        }
    }
    
    sec
}
