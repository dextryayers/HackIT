use regex::Regex;
use std::collections::HashSet;

pub struct Parser {
    param_regex: Regex,
}

impl Parser {
    pub fn new() -> Self {
        Self {
            param_regex: Regex::new(r"(\?|\&)([^=]+)\=([^&\s]+)").unwrap(),
        }
    }

    pub fn extract_params(&self, url: &str) -> bool {
        self.param_regex.is_match(url)
    }

    pub fn fuzzify_url(&self, url: &str) -> String {
        // Replace parameter values with FUZZ
        self.param_regex.replace_all(url, "$1$2=FUZZ").to_string()
    }

    pub fn dedupe(&self, urls: Vec<String>) -> HashSet<String> {
        urls.into_iter().collect()
    }
}
