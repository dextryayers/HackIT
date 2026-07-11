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
mod whois;
mod ssl_tls;
mod http_headers;
mod cve_search;
mod breach_check;
mod subdomain_takeover;
mod tech_fingerprint;
mod api_discovery;
mod cloud_buckets;
mod social_search;
mod paste_scan;
mod git_discovery;
mod dns_zone_transfer;
mod cors_check;
mod redirect_trace;
mod cookie_audit;
mod email_security;
mod asn_network;
mod js_analysis;
mod dir_enum;

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
    /// Module configuration as JSON string
    #[arg(long = "config", global = true)]
    config: Option<String>,
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
    Whois { domain: String },
    SslTls { hostname: String },
    HttpHeaders { url: String },
    CveSearch { target: String },
    BreachCheck { target: String },
    SubdomainTakeover { target: String },
    TechFingerprint { url: String },
    ApiDiscovery { url: String },
    CloudBuckets { target: String },
    SocialSearch { username: String },
    PasteScan { target: String },
    GitDiscovery { url: String },
    DnsZoneTransfer { domain: String },
    CorsCheck { url: String },
    RedirectTrace { url: String },
    CookieAudit { url: String },
    EmailSecurity { domain: String },
    AsnNetwork { target: String },
    JsAnalysis { url: String },
    DirEnum { url: String },
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

async fn run_module_async<T: serde::Serialize>(label: &str, f: impl std::future::Future<Output = T>) -> T {
    emit("progress", label, "running");
    let r = f.await;
    if progress_enabled() {
        let json = serde_json::to_value(&r).unwrap_or_default();
        emit_result(label, &json);
        emit("progress", label, "done");
    } else {
        println!("{}", serde_json::to_string(&r).unwrap());
    }
    r
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::ListModules => {
            let modules = vec!["subdomain","ports","dns","email","webtech","crawl","sensitive","secret","waf","social","crtsh","vuln","cloud","whois","ssl_tls","http_headers","cve_search","breach_check","subdomain_takeover","tech_fingerprint","api_discovery","cloud_buckets","social_search","paste_scan","git_discovery","dns_zone_transfer","cors_check","redirect_trace","cookie_audit","email_security","asn_network","js_analysis","dir_enum"];
            println!("{}", serde_json::to_string(&modules).unwrap());
        }
        Commands::Subdomain { domain } => { run_module_async("subdomain", subdomain::enumerate(&domain)).await; }
        Commands::Ports { host } => {
            let (prts, bann) = tokio::join!(ports::scan(&host), ports::banner_grab(&host));
            let result = serde_json::json!({"ports": prts, "banners": bann});
            if progress_enabled() { emit_result("ports", &result); } else { println!("{}", serde_json::to_string(&result).unwrap()); }
        }
        Commands::Dns { domain } => { run_module_async("dns", dns::enumerate(&domain)).await; }
        Commands::Email { domain } => { run_module_async("email", email::discover(&domain)).await; }
        Commands::Webtech { url } => { run_module_async("webtech", webtech::detect(&url)).await; }
        Commands::Crawl { url } => { run_module_async("crawl", crawl::analyze(&url)).await; }
        Commands::Sensitive { url } => { run_module_async("sensitive", sensitive::scan(&url)).await; }
        Commands::Secret { url } => { run_module_async("secret", secret::scan(&url)).await; }
        Commands::Waf { url } => { run_module_async("waf", waf::detect(&url)).await; }
        Commands::Social { username } => { run_module_async("social", social::check(&username)).await; }
        Commands::Crtsh { domain } => { run_module_async("crtsh", crtsh::search(&domain)).await; }
        Commands::Vuln { target } => { run_module_async("vuln", vuln::scan(&target)).await; }
        Commands::Cloud { target } => { run_module_async("cloud", cloud::detect(&target)).await; }
        Commands::Whois { domain } => { run_module_async("whois", whois::lookup(&domain)).await; }
        Commands::SslTls { hostname } => { run_module_async("ssl_tls", ssl_tls::scan(&hostname)).await; }
        Commands::HttpHeaders { url } => { run_module_async("http_headers", http_headers::analyze(&url)).await; }
        Commands::CveSearch { target } => { run_module_async("cve_search", cve_search::search(&target)).await; }
        Commands::BreachCheck { target } => { run_module_async("breach_check", breach_check::check(&target)).await; }
        Commands::SubdomainTakeover { target } => { run_module_async("subdomain_takeover", subdomain_takeover::check(&target)).await; }
        Commands::TechFingerprint { url } => { run_module_async("tech_fingerprint", tech_fingerprint::fingerprint(&url)).await; }
        Commands::ApiDiscovery { url } => { run_module_async("api_discovery", api_discovery::discover(&url)).await; }
        Commands::CloudBuckets { target } => { run_module_async("cloud_buckets", cloud_buckets::enumerate(&target)).await; }
        Commands::SocialSearch { username } => { run_module_async("social_search", social_search::search(&username)).await; }
        Commands::PasteScan { target } => { run_module_async("paste_scan", paste_scan::scan(&target)).await; }
        Commands::GitDiscovery { url } => { run_module_async("git_discovery", git_discovery::discover(&url)).await; }
        Commands::DnsZoneTransfer { domain } => { run_module_async("dns_zone_transfer", dns_zone_transfer::enumerate(&domain)).await; }
        Commands::CorsCheck { url } => { run_module_async("cors_check", cors_check::check(&url)).await; }
        Commands::RedirectTrace { url } => { run_module_async("redirect_trace", redirect_trace::trace(&url)).await; }
        Commands::CookieAudit { url } => { run_module_async("cookie_audit", cookie_audit::audit(&url)).await; }
        Commands::EmailSecurity { domain } => { run_module_async("email_security", email_security::check(&domain)).await; }
        Commands::AsnNetwork { target } => { run_module_async("asn_network", asn_network::lookup(&target)).await; }
        Commands::JsAnalysis { url } => { run_module_async("js_analysis", js_analysis::analyze(&url)).await; }
        Commands::DirEnum { url } => { run_module_async("dir_enum", dir_enum::enumerate(&url)).await; }
        Commands::All { target, modules: _ } => {
            let start = Instant::now();
            let _config: common::ScanConfig = cli.config.as_ref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();

            let (subs, prts, bann, dns_res, eml, web, crw, sen, sec, wf, soc, crt, vln, cld, who, stls, hh, cve, brch, sto, tf, ad, cb, ss, ps, gd, dzt, crsch, rtrace, caudit, es, asn, jsa, de) = tokio::join!(
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
                whois::lookup(&target),
                ssl_tls::scan(&target),
                http_headers::analyze(&target),
                cve_search::search(&target),
                breach_check::check(&target),
                subdomain_takeover::check(&target),
                tech_fingerprint::fingerprint(&target),
                api_discovery::discover(&target),
                cloud_buckets::enumerate(&target),
                social_search::search(&target),
                paste_scan::scan(&target),
                git_discovery::discover(&target),
                dns_zone_transfer::enumerate(&target),
                cors_check::check(&target),
                redirect_trace::trace(&target),
                cookie_audit::audit(&target),
                email_security::check(&target),
                asn_network::lookup(&target),
                js_analysis::analyze(&target),
                dir_enum::enumerate(&target),
            );

            let elapsed = start.elapsed().as_millis() as u64;
            let result = serde_json::json!({
                "target": target, "duration_ms": elapsed,
                "subdomains": subs, "ports": prts, "banners": bann,
                "dns": dns_res, "emails": eml, "webtech": web,
                "crawl": crw, "sensitive": sen, "secrets": sec,
                "waf": wf, "social": soc, "crtsh": crt,
                "vulns": vln, "cloud": cld,
                "whois": who, "ssl_tls": stls, "http_headers": hh,
                "cve_search": cve, "breach_check": brch,
                "subdomain_takeover": sto, "tech_fingerprint": tf,
                "api_discovery": ad, "cloud_buckets": cb,
                "social_search": ss, "paste_scan": ps,
                "git_discovery": gd, "dns_zone_transfer": dzt,
                "cors_check": crsch, "redirect_trace": rtrace,
                "cookie_audit": caudit, "email_security": es,
                "asn_network": asn, "js_analysis": jsa,
                "dir_enum": de,
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
