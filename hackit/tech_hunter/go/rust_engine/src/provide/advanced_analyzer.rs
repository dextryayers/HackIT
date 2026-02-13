use std::collections::HashMap;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AdvancedAnalysis {
    pub suspected_behaviours: Vec<String>,
    pub security_score: u8,
    pub technology_depth: Vec<String>,
}

pub fn analyze_behaviours(body: &str, headers: &HashMap<String, String>) -> AdvancedAnalysis {
    let mut analysis = AdvancedAnalysis::default();
    let mut score = 100;

    // 1. Detect Anti-Bot / WAF Behaviours
    if body.contains("_cf_chl_opt") || headers.contains_key("cf-ray") {
        analysis.suspected_behaviours.push("Cloudflare Protection Active".to_string());
    }
    if body.contains("distil_ident") || body.contains("distil_js_path") {
        analysis.suspected_behaviours.push("Distil Networks Anti-Bot".to_string());
    }
    if body.contains("window._px") || body.contains("px-captcha") {
        analysis.suspected_behaviours.push("PerimeterX Bot Protection".to_string());
    }

    // 2. Security Analysis
    if !headers.contains_key("strict-transport-security") { score -= 10; }
    if !headers.contains_key("content-security-policy") { score -= 15; }
    if !headers.contains_key("x-frame-options") { score -= 5; }
    
    analysis.security_score = score;

    // 3. Depth Technology Detection
    if body.contains("react-root") || body.contains("_reactRootContainer") {
        analysis.technology_depth.push("React (Hydrated)".to_string());
    }
    if body.contains("window.__NUXT__") {
        analysis.technology_depth.push("Nuxt.js (SSR)".to_string());
    }
    if body.contains("window.__NEXT_DATA__") {
        analysis.technology_depth.push("Next.js (SSR/Static)".to_string());
    }

    analysis
}
