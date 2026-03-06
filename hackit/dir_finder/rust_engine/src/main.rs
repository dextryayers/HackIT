mod config;
mod scanner;

use config::ScanConfig;
use std::env;
use std::fs;
use std::collections::HashMap;
use colored::Colorize;
use walkdir::WalkDir;

fn load_all_payloads() -> (Vec<String>, String) {
    let mut all_paths = Vec::new();
    let db_paths = vec!["db", "../db", "../../db", "hackit/dir_finder/db"];
    let mut found_db = String::new();

    for p in db_paths {
        if std::path::Path::new(p).exists() {
            found_db = p.to_string();
            break;
        }
    }

    if found_db.is_empty() {
        return (all_paths, found_db);
    }
    
    for entry in WalkDir::new(&found_db).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("txt") {
            // Skip user-agents.txt
            if path.file_name().and_then(|s| s.to_str()) == Some("user-agents.txt") {
                continue;
            }
            
            if let Ok(content) = fs::read_to_string(path) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        all_paths.push(trimmed.to_string());
                    }
                }
            }
        }
    }
    (all_paths, found_db)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        println!("HackIt Rust Turbo Engine");
        println!("Usage: {} <target_url> [threads] [timeout_ms]", args[0]);
        return;
    }

    let target = args[1].clone();
    let threads = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(50);
    let timeout = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(10000);

    // Load all payloads from db/ recursively
    let (paths, found_db) = load_all_payloads();
    
    let paths = if paths.is_empty() {
        println!("{}", "[!] No payloads found in db/ directory, using defaults".yellow());
        vec![
            ".env".to_string(),
            ".git/config".to_string(),
            "admin/".to_string(),
            "login/".to_string(),
            "robots.txt".to_string(),
        ]
    } else {
        println!("{} Loaded {} total payloads from {} directory recursively", "[+]".green(), paths.len(), found_db);
        paths
    };

    let config = ScanConfig {
        target,
        paths,
        method: "GET".to_string(),
        data: None,
        headers: HashMap::new(),
        cookie: None,
        auth: None,
        proxy: None,
        user_agent: None,
        threads,
        timeout_ms: timeout,
        delay_ms: 0,
        retries: 1,
        random_agent: true,
        http2: false,
        follow_redirects: false,
        max_redirects: 5,
        extensions: vec![],
        recursive: false,
        depth: 0,
        exclude_status: vec![],
        include_status: vec![],
        exclude_length: vec![],
        include_length: vec![],
        detect_waf: false,
        detect_tech: false,
        detect_cms: false,
        detect_backup: false,
        smart_filter: false,
        fuzz_param: None,
        api_mode: false,
        json_body: false,
        graphql: false,
        rate_limit: None,
        auto_wordlist: false,
        crawl: false,
        extract_js: false,
    };

    println!("{} Rust Turbo Assistant starting on: {}", "[*]".cyan(), config.target);
    scanner::run_scan(config).await;
    println!("\n{} Rust Scan Complete.", "[*]".cyan());
}
