use serde_json;

pub struct Harvester {
    domain: String,
}

impl Harvester {
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
        }
    }

    pub fn generate_report(&self, urls: Vec<String>) -> String {
        // Prepare data for the Go Shaper in JSON format
        serde_json::to_string(&urls).unwrap_or_else(|_| "[]".to_string())
    }
}
