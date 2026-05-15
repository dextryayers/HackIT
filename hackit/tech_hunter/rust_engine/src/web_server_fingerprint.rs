use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct ServerFingerprint {
    pub framework: String,
    pub cms: String,
    pub version_confidence: i32,
}

pub fn get_fingerprint_json(headers_raw: &str) -> String {
    let headers_lower = headers_raw.to_lowercase();
    
    let mut framework = "Unknown".to_string();
    let mut cms = "None".to_string();
    let mut confidence = 0;

    if headers_lower.contains("wp-") || headers_lower.contains("wordpress") {
        cms = "WordPress".to_string();
        confidence += 80;
    } else if headers_lower.contains("drupal") {
        cms = "Drupal".to_string();
        confidence += 85;
    }

    if headers_lower.contains("laravel") || headers_lower.contains("xsrf-token") {
        framework = "Laravel (PHP)".to_string();
        confidence += 70;
    } else if headers_lower.contains("express") || headers_lower.contains("connect.sid") {
        framework = "Express.js (Node)".to_string();
        confidence += 70;
    }

    let result = ServerFingerprint { framework, cms, version_confidence: confidence };
    serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string())
}
