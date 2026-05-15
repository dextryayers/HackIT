use std::collections::HashMap;

pub struct ReconIntelligence {
    pub score: i32,
    pub signals: Vec<String>,
}

pub fn analyze_intelligence(body: &str, headers: &HashMap<String, String>) -> ReconIntelligence {
    let mut score = 0;
    let mut signals = Vec::new();

    // Signal: Hidden Admin Paths
    if body.contains("/admin/") || body.contains("/wp-admin/") {
        score += 10;
        signals.push("AdminEndpointFound".to_string());
    }

    // Signal: Technology Conflict
    if headers.contains_key("Server") && headers.get("Server").unwrap().contains("nginx") {
        if headers.contains_key("X-Powered-By") && headers.get("X-Powered-By").unwrap().contains("ASP.NET") {
            score += 20;
            signals.push("StrangeTechMix_Nginx_ASP".to_string());
        }
    }

    // Signal: Security Headers
    if !headers.contains_key("Content-Security-Policy") {
        score += 5;
        signals.push("MissingCSP".to_string());
    }

    ReconIntelligence { score, signals }
}
