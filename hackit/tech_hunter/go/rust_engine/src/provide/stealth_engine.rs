use std::collections::HashMap;
use rand::seq::SliceRandom;

pub struct StealthConfig {
    pub user_agents: Vec<String>,
    pub accept_headers: Vec<String>,
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            user_agents: vec![
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36".to_string(),
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36".to_string(),
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0".to_string(),
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1".to_string(),
            ],
            accept_headers: vec![
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".to_string(),
                "application/json, text/plain, */*".to_string(),
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string(),
            ],
        }
    }
}

pub fn get_random_stealth_headers() -> HashMap<String, String> {
    let mut rng = rand::thread_rng();
    let config = StealthConfig::default();
    let mut headers = HashMap::new();

    headers.insert("User-Agent".to_string(), config.user_agents.choose(&mut rng).unwrap().clone());
    headers.insert("Accept".to_string(), config.accept_headers.choose(&mut rng).unwrap().clone());
    headers.insert("Accept-Language".to_string(), "en-US,en;q=0.9".to_string());
    headers.insert("Sec-Ch-Ua".to_string(), "\"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"121\", \"Chromium\";v=\"121\"".to_string());
    headers.insert("Sec-Ch-Ua-Mobile".to_string(), "?0".to_string());
    headers.insert("Sec-Ch-Ua-Platform".to_string(), "\"Windows\"".to_string());
    headers.insert("Sec-Fetch-Dest".to_string(), "document".to_string());
    headers.insert("Sec-Fetch-Mode".to_string(), "navigate".to_string());
    headers.insert("Sec-Fetch-Site".to_string(), "none".to_string());
    headers.insert("Sec-Fetch-User".to_string(), "?1".to_string());
    headers.insert("Upgrade-Insecure-Requests".to_string(), "1".to_string());
    
    headers
}
