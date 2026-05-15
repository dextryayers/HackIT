use std::collections::HashMap;
use crate::TechInfo;

pub fn analyze(body: &str, headers: &HashMap<String, String>) -> HashMap<String, TechInfo> {
    let mut detected = HashMap::new();

    // Re-implementing core signatures
    if body.contains("wp-content") || body.contains("wp-includes") {
        detected.insert("WordPress".to_string(), TechInfo {
            name: "WordPress".to_string(),
            confidence: 100,
            category: "CMS".to_string(),
            version: None,
        });
    }

    if let Some(server) = headers.get("Server") {
        detected.insert(server.clone(), TechInfo {
            name: server.clone(),
            confidence: 100,
            category: "Web Server".to_string(),
            version: None,
        });
    }

    detected
}
