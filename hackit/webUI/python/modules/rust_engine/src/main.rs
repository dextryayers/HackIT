mod common;
mod subdomain;
mod ports;
mod dns;
mod email;
mod webtech;
mod crawl;
mod sensitive;
mod secret;
mod waf;
mod social;
mod crtsh;

use clap::{Parser, Subcommand};
use std::time::Instant;

#[derive(Parser)]
#[command(name = "hackit_engine", version = "1.0.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Subdomain enumeration via crt.sh + DNS brute force
    Subdomain { domain: String },
    /// Port scanning (top 100 ports)
    Ports { host: String },
    /// DNS record enumeration
    Dns { domain: String },
    /// Email pattern discovery
    Email { domain: String },
    /// Web technology detection
    Webtech { url: String },
    /// Web crawler - extract links, titles, metadata
    Crawl { url: String, depth: Option<u32> },
    /// Sensitive file/directory discovery
    Sensitive { url: String },
    /// Secret/API key scanner in page content
    Secret { url: String },
    /// WAF/CDN detection
    Waf { url: String },
    /// Social media username checker
    Social { username: String },
    /// Deep certificate transparency search
    Crtsh { domain: String },
    /// All-in-one scan (parallel)
    All { target: String },
}

fn main() {
    let cli = Cli::parse();
    let rt = tokio::runtime::Runtime::new().unwrap();

    match cli.command {
        Commands::Subdomain { domain } => {
            let r = rt.block_on(subdomain::enumerate(&domain));
            println!("{}", serde_json::to_string(&r).unwrap());
        }
        Commands::Ports { host } => {
            let r = rt.block_on(ports::scan(&host));
            println!("{}", serde_json::to_string(&r).unwrap());
        }
        Commands::Dns { domain } => {
            let r = rt.block_on(dns::enumerate(&domain));
            println!("{}", serde_json::to_string(&r).unwrap());
        }
        Commands::Email { domain } => {
            let r = rt.block_on(email::discover(&domain));
            println!("{}", serde_json::to_string(&r).unwrap());
        }
        Commands::Webtech { url } => {
            let r = rt.block_on(webtech::detect(&url));
            println!("{}", serde_json::to_string(&r).unwrap());
        }
        Commands::Crawl { url, depth: _ } => {
            let r = rt.block_on(crawl::crawl_website(&url));
            println!("{}", serde_json::to_string(&r).unwrap());
        }
        Commands::Sensitive { url } => {
            let r = rt.block_on(sensitive::scan(&url));
            println!("{}", serde_json::to_string(&r).unwrap());
        }
        Commands::Secret { url } => {
            let r = rt.block_on(secret::scan(&url));
            println!("{}", serde_json::to_string(&r).unwrap());
        }
        Commands::Waf { url } => {
            let r = rt.block_on(waf::detect(&url));
            println!("{}", serde_json::to_string(&r).unwrap());
        }
        Commands::Social { username } => {
            let r = rt.block_on(social::check(&username));
            println!("{}", serde_json::to_string(&r).unwrap());
        }
        Commands::Crtsh { domain } => {
            let r = rt.block_on(crtsh::search(&domain));
            println!("{}", serde_json::to_string(&r).unwrap());
        }
        Commands::All { target } => {
            let start = Instant::now();
            let (subs, prts, dns_res, eml, web, crw, sen, wf, crt) = rt.block_on(async {
                tokio::join!(
                    subdomain::enumerate(&target),
                    ports::scan(&target),
                    dns::enumerate(&target),
                    email::discover(&target),
                    webtech::detect(&target),
                    crawl::crawl_website(&target),
                    sensitive::scan(&target),
                    waf::detect(&target),
                    crtsh::search(&target),
                )
            });
            let elapsed = start.elapsed().as_millis() as u64;
            let result = serde_json::json!({
                "target": target, "duration_ms": elapsed,
                "subdomains": subs, "ports": prts, "dns": dns_res, "emails": eml,
                "webtech": web, "crawl": crw, "sensitive": sen,
                "waf": wf, "crtsh": crt,
            });
            println!("{}", serde_json::to_string(&result).unwrap());
        }
    }
}
