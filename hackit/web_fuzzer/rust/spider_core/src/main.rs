use clap::Parser as ClapParser;
use std::collections::HashSet;

mod crawler;
mod intel_engine;
mod secret_finder;
mod dom_analyzer;

use crawler::AdvancedCrawler;
use intel_engine::IntelEngine;

#[derive(ClapParser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Domain to harvest
    domain: String,

    /// Enable verbose output
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Enable high-anonymity masking
    #[arg(long, default_value_t = false)]
    mask: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut all_urls = HashSet::new();

    if args.verbose {
        println!("[*] RUST-SPIDER: Booting elite reconnaissance cluster for {}...", args.domain);
    }

    // 1. Initialize Engines
    let intel = IntelEngine::new();
    let mut crawler = AdvancedCrawler::new(2);

    // 2. Phase 1: Passive Harvesting (Wayback/Intel)
    if args.verbose { println!("[*] PHASE 1: Harvesting historical intelligence..."); }
    let wayback_urls = intel.fetch_wayback(&args.domain).await;
    let mut js_urls = Vec::new();
    
    for u in wayback_urls {
        if u.ends_with(".js") {
            js_urls.push(u.clone());
        }
        all_urls.insert(intel.fuzzify(&u));
    }

    // 3. Phase 2: Active Dynamic Crawling
    if args.verbose { println!("[*] PHASE 2: Executing recursive active crawling..."); }
    let crawled_urls = crawler.crawl(&format!("http://{}", args.domain)).await;
    for u in crawled_urls {
        all_urls.insert(intel.fuzzify(&u));
    }

    // 4. Phase 3: JS Parameter Mining
    if args.verbose { println!("[*] PHASE 3: Mining deep JavaScript parameters..."); }
    let hidden_params = intel.mine_js_params(js_urls).await;
    for p in hidden_params {
        all_urls.insert(format!("http://{}/?{}=FUZZ", args.domain, p));
    }

    if all_urls.is_empty() {
        if args.verbose {
            println!("[!] RECON: No tactical targets discovered for this domain.");
        }
    }

    // Output standardized results
    for target in all_urls {
        println!("{}", target);
    }

    Ok(())
}
