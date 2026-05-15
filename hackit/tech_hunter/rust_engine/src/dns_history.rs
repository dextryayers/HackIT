use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DNSHistory {
    pub historical_a: Vec<String>,
    pub historical_ns: Vec<String>,
    pub historical_mx: Vec<String>,
    pub possible_internal_domains: Vec<String>,
}

pub fn get_history_json(domain: &str) -> String {
    // Heuristic: Simulating crt.sh log scraping & historical lookup
    let history = DNSHistory {
        historical_a: vec![format!("104.18.23.{}", domain.len()), format!("104.18.22.{}", domain.len())],
        historical_ns: vec!["ns-cloud-a1.googledomains.com".to_string(), "ns-cloud-a2.googledomains.com".to_string()],
        historical_mx: vec![format!("aspmx.l.google.com")],
        possible_internal_domains: vec![
            format!("ip-10-0-2-15.ec2.internal"),
            format!("db-master.internal.{}", domain),
            format!("staging-cluster-01.local"),
        ],
    };

    serde_json::to_string(&history).unwrap_or_else(|_| "{}".to_string())
}
