use std::collections::HashMap;

pub fn analyze_behavior(headers: &HashMap<String, String>, status: i32) -> Vec<String> {
    let mut behaviors = Vec::new();

    // Behavior: Rate Limiting
    if status == 429 || headers.contains_key("retry-after") || headers.contains_key("x-ratelimit-remaining") {
        behaviors.push("ActiveRateLimitingDetected".to_string());
    }

    // Behavior: Unusual Server Header
    if let Some(server) = headers.get("server") {
        if server.len() > 50 {
            behaviors.push("SuspiciouslyLongServerHeader".to_string());
        }
    }

    // Behavior: Cache Poisoning Potential
    if headers.contains_key("x-forwarded-host") || headers.contains_key("x-host") {
        behaviors.push("CachePoisoningVulnerability_Potential".to_string());
    }

    behaviors
}
