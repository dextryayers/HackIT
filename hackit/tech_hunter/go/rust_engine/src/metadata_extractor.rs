pub struct SiteMetadata {
    pub description: String,
    pub keywords: Vec<String>,
    pub industry_hint: String,
    pub phone: String,
    pub address: String,
}

pub fn extract_metadata(body: &str) -> SiteMetadata {
    let mut description = String::new();
    let mut keywords = Vec::new();
    let mut industry_hint = "General Technology".to_string();

    // Heuristic: Extract meta description
    if let Some(start) = body.find("<meta name=\"description\" content=\"") {
        let content_start = start + 34;
        if let Some(end) = body[content_start..].find("\"") {
            description = body[content_start..content_start + end].to_string();
        }
    }

    // Heuristic: Extract meta keywords
    if let Some(start) = body.find("<meta name=\"keywords\" content=\"") {
        let content_start = start + 31;
        if let Some(end) = body[content_start..].find("\"") {
            keywords = body[content_start..content_start + end]
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
        }
    }

    // Industry Inference Logic
    let industry_signals = vec![
        ("Finance", vec!["bank", "crypto", "trading", "finance", "investment"]),
        ("Health", vec!["medical", "hospital", "health", "doctor", "clinic"]),
        ("E-commerce", vec!["shop", "store", "buy", "sell", "checkout", "cart"]),
        ("SaaS", vec!["platform", "software", "api", "dashboard", "automate"]),
    ];

    let body_lower = body.to_lowercase();
    for (industry, signals) in industry_signals {
        for signal in signals {
            if body_lower.contains(signal) {
                industry_hint = industry.to_string();
                break;
            }
        }
    }

    // Heuristic: Extract Phone (Simulated pattern)
    let mut phone = "REDACTED".to_string();
    if let Some(pos) = body.find("tel:") {
        let start = pos + 4;
        if let Some(end) = body[start..].find("\"") {
            phone = body[start..start+end].to_string();
        }
    }

    SiteMetadata {
        description,
        keywords,
        industry_hint,
        phone,
        address: "Global / Inferred from Content".to_string(),
    }
}
