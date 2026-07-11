#![allow(dead_code)]
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
mod vuln;
mod cloud;

use clap::{Parser, Subcommand};
use std::time::Instant;

#[derive(Parser)]
#[command(name = "hackit_engine", version = "1.0.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Enable progress JSON lines on stdout
    #[arg(short = 'p', long = "progress", global = true)]
    progress: bool,
}

#[derive(Subcommand)]
enum Commands {
    Subdomain { domain: String },
    Ports { host: String },
    Dns { domain: String },
    Email { domain: String },
    Webtech { url: String },
    Crawl { url: String },
    Sensitive { url: String },
    Secret { url: String },
    Waf { url: String },
    Social { username: String },
    Crtsh { domain: String },
    Vuln { target: String },
    Cloud { target: String },
    All { target: String, modules: Option<String> },
    ListModules,
}

fn progress_enabled() -> bool {
    std::env::args().any(|a| a == "--progress" || a == "-p")
}

fn emit(event: &str, module: &str, status: &str) {
    if progress_enabled() {
        println!("{}", serde_json::json!({"event": event, "module": module, "status": status, "ts": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64}));
    }
}

fn emit_result(module: &str, data: &serde_json::Value) {
    if progress_enabled() {
        println!("{}", serde_json::json!({"event": "result", "module": module, "data": data}));
    }
}

fn run_module<T: serde::Serialize>(label: &str, f: impl std::future::Future<Output = T>) -> T {
    emit("progress", label, "running");
    let r = tokio::runtime::Runtime::new().unwrap().block_on(f);
    if progress_enabled() {
        let json = serde_json::to_value(&r).unwrap_or_default();
        emit_result(label, &json);
        emit("progress", label, "done");
    } else {
        println!("{}", serde_json::to_string(&r).unwrap());
    }
    r
}

fn main() {
    let cli = Cli::parse();
    let rt = tokio::runtime::Runtime::new().unwrap();

    match cli.command {
        Commands::ListModules => {
            let modules = vec!["subdomain","ports","dns","email","webtech","crawl","sensitive","secret","waf","social","crtsh","vuln","cloud"];
            println!("{}", serde_json::to_string(&modules).unwrap());
        }
        Commands::Subdomain { domain } => { run_module("subdomain", subdomain::enumerate(&domain)); }
        Commands::Ports { host } => {
            let ports_fut = ports::scan(&host);
            let banners_fut = ports::banner_grab(&host);
            let (prts, bann) = rt.block_on(async { tokio::join!(ports_fut, banners_fut) });
            let result = serde_json::json!({"ports": prts, "banners": bann});
            if progress_enabled() { emit_result("ports", &result); } else { println!("{}", serde_json::to_string(&result).unwrap()); }
        }
        Commands::Dns { domain } => { run_module("dns", dns::enumerate(&domain)); }
        Commands::Email { domain } => { run_module("email", email::discover(&domain)); }
        Commands::Webtech { url } => { run_module("webtech", webtech::detect(&url)); }
        Commands::Crawl { url } => { run_module("crawl", crawl::analyze(&url)); }
        Commands::Sensitive { url } => { run_module("sensitive", sensitive::scan(&url)); }
        Commands::Secret { url } => { run_module("secret", secret::scan(&url)); }
        Commands::Waf { url } => { run_module("waf", waf::detect(&url)); }
        Commands::Social { username } => { run_module("social", social::check(&username)); }
        Commands::Crtsh { domain } => { run_module("crtsh", crtsh::search(&domain)); }
        Commands::Vuln { target } => { run_module("vuln", vuln::scan(&target)); }
        Commands::Cloud { target } => { run_module("cloud", cloud::detect(&target)); }
        Commands::All { target, modules: _ } => {
            let start = Instant::now();

            let (subs, prts, bann, dns_res, eml, web, crw, sen, sec, wf, soc, crt, vln, cld) = rt.block_on(async {
                tokio::join!(
                    subdomain::enumerate(&target),
                    ports::scan(&target),
                    ports::banner_grab(&target),
                    dns::enumerate(&target),
                    email::discover(&target),
                    webtech::detect(&target),
                    crawl::analyze(&target),
                    sensitive::scan(&target),
                    secret::scan(&target),
                    waf::detect(&target),
                    social::check(&target),
                    crtsh::search(&target),
                    vuln::scan(&target),
                    cloud::detect(&target),
                )
            });

            let elapsed = start.elapsed().as_millis() as u64;
            let result = serde_json::json!({
                "target": target, "duration_ms": elapsed,
                "subdomains": subs, "ports": prts, "banners": bann,
                "dns": dns_res, "emails": eml, "webtech": web,
                "crawl": crw, "sensitive": sen, "secrets": sec,
                "waf": wf, "social": soc, "crtsh": crt,
                "vulns": vln, "cloud": cld,
            });
            if progress_enabled() {
                emit("progress", "all", "done");
                println!("{}", serde_json::json!({"event": "complete", "data": result}));
            } else {
                println!("{}", serde_json::to_string(&result).unwrap());
            }
        }
    }
}
