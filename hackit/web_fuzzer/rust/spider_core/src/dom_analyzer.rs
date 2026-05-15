use scraper::{Html, Selector};
use std::collections::HashSet;

pub struct DomAnalyzer;

impl DomAnalyzer {
    pub fn analyze_forms(html: &str) -> HashSet<String> {
        let mut params = HashSet::new();
        let fragment = Html::parse_fragment(html);
        
        // 1. Hidden Inputs
        let hidden_selector = Selector::parse("input[type='hidden']").unwrap();
        for element in fragment.select(&hidden_selector) {
            if let Some(name) = element.value().attr("name") {
                params.insert(name.to_string());
            }
        }

        // 2. Data Attributes
        let any_selector = Selector::parse("*").unwrap();
        for element in fragment.select(&any_selector) {
            for (attr, _) in element.value().attrs() {
                if attr.starts_with("data-") {
                    params.insert(attr.to_string());
                }
            }
        }

        // 3. Form fields (name, id)
        let form_selector = Selector::parse("input, select, textarea").unwrap();
        for element in fragment.select(&form_selector) {
            if let Some(name) = element.value().attr("name") {
                params.insert(name.to_string());
            }
            if let Some(id) = element.value().attr("id") {
                params.insert(id.to_string());
            }
        }

        params
    }
}
