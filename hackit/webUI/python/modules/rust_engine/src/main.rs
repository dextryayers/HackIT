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
mod email_breach_check;
mod cdn_discovery;
mod web_performance;
mod dns_sec_check;
mod ip_reputation;
mod leak_detection;
mod csp_analyzer;
mod graph_api_scan;
mod firebase_scanner;
mod mobile_app_scan;
mod social_media_check;
mod email_intel;
mod dns_intel;
mod darkweb_search;
mod ssl_intel;
mod web_intel;
mod google_dorks;
mod link_extractor;
mod web_form_discovery;
mod http_method_fuzzer;
mod web_backup_scanner;
mod domain_permutation;
mod http_archive_scanner;

use clap::{Parser, Subcommand};
use std::collections::HashSet;
use std::time::Instant;

const ALL_MODULES: &[&str] = &[
    "subdomain","ports","dns","email","webtech","crawl","sensitive","secret","waf","social",
    "crtsh","vuln","cloud","whois","ssl_tls","http_headers","cve_search","breach_check",
    "subdomain_takeover","tech_fingerprint","api_discovery","cloud_buckets","social_search",
    "paste_scan","git_discovery","dns_zone_transfer","cors_check","redirect_trace",
    "cookie_audit","email_security","asn_network","js_analysis","dir_enum","cdn_discovery","web_performance",
    "dns_sec_check","ip_reputation","email_breach_check","graph_api_scan","mobile_app_scan","firebase_scanner","leak_detection","csp_analyzer",
    "social_media_check","email_intel","dns_intel","darkweb_search","ssl_intel","web_intel","google_dorks",
    "link_extractor","web_form_discovery","http_method_fuzzer","web_backup_scanner","domain_permutation","http_archive_scanner",
];

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
    CdnDiscovery { target: String },
    WebPerformance { url: String },
    DnsSecCheck { domain: String },
    IpReputation { ip: String },
    EmailBreachCheck { email: String },
    GraphApiScan { target: String },
    MobileAppScan { target: String },
    FirebaseScan { target: String },
    LeakDetection { target: String },
    CspAnalyze { url: String },
    SocialMediaCheck { username: String },
    EmailIntel { domain: String },
    DnsIntel { domain: String },
    DarkwebSearch { query: String },
    SslIntel { hostname: String },
    WebIntel { domain: String },
    GoogleDorks { domain: String },
    LinkExtractor { target: String },
    WebFormDiscovery { target: String },
    HttpMethodFuzzer { target: String },
    WebBackupScanner { target: String },
    DomainPermutation { target: String },
    HttpArchiveScanner { target: String },
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

fn safe_json<T: serde::Serialize>(val: &T) -> String {
    serde_json::to_string(val).unwrap_or_else(|_| "{}".to_string())
}

fn safe_json_value<T: serde::Serialize>(val: &T) -> serde_json::Value {
    serde_json::to_value(val).unwrap_or(serde_json::Value::Object(Default::default()))
}

async fn run_module_async<T: serde::Serialize>(label: &str, f: impl std::future::Future<Output = T>) -> T {
    emit("progress", label, "running");
    let r = f.await;
    if progress_enabled() {
        emit_result(label, &safe_json_value(&r));
        emit("progress", label, "done");
    } else {
        println!("{}", safe_json(&r));
    }
    r
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::ListModules => {
            let modules = ALL_MODULES.to_vec();
            println!("{}", safe_json(&modules));
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
        Commands::WebPerformance { url } => { run_module_async("web_performance", web_performance::analyze(&url)).await; }
        Commands::DnsSecCheck { domain } => { run_module_async("dns_sec_check", dns_sec_check::check(&domain)).await; }
        Commands::IpReputation { ip } => { run_module_async("ip_reputation", ip_reputation::check(&ip)).await; }
        Commands::CdnDiscovery { target } => { run_module_async("cdn_discovery", cdn_discovery::discover(&target)).await; }
        Commands::GraphApiScan { target } => { run_module_async("graph_api_scan", graph_api_scan::scan(&target)).await; }
        Commands::EmailBreachCheck { email } => { run_module_async("email_breach_check", email_breach_check::check(&email)).await; }
        Commands::MobileAppScan { target } => { run_module_async("mobile_app_scan", mobile_app_scan::scan(&target)).await; }
        Commands::FirebaseScan { target } => { run_module_async("firebase_scanner", firebase_scanner::scan(&target)).await; }
        Commands::LeakDetection { target } => { run_module_async("leak_detection", leak_detection::detect(&target)).await; }
        Commands::CspAnalyze { url } => { run_module_async("csp_analyzer", csp_analyzer::analyze(&url)).await; }
        Commands::SocialMediaCheck { username } => { run_module_async("social_media_check", social_media_check::scan(&username, &common::ScanConfig::default())).await; }
        Commands::EmailIntel { domain } => { run_module_async("email_intel", email_intel::scan(&domain, &common::ScanConfig::default())).await; }
        Commands::DnsIntel { domain } => { run_module_async("dns_intel", dns_intel::scan(&domain, &common::ScanConfig::default())).await; }
        Commands::DarkwebSearch { query } => { run_module_async("darkweb_search", darkweb_search::scan(&query, &common::ScanConfig::default())).await; }
        Commands::SslIntel { hostname } => { run_module_async("ssl_intel", ssl_intel::scan(&hostname, &common::ScanConfig::default())).await; }
        Commands::WebIntel { domain } => { run_module_async("web_intel", web_intel::scan(&domain, &common::ScanConfig::default())).await; }
        Commands::GoogleDorks { domain } => { run_module_async("google_dorks", google_dorks::scan(&domain, &common::ScanConfig::default())).await; }
        Commands::LinkExtractor { target } => { run_module_async("link_extractor", link_extractor::scan(&target, &common::ScanConfig::default())).await; }
        Commands::WebFormDiscovery { target } => { run_module_async("web_form_discovery", web_form_discovery::scan(&target, &common::ScanConfig::default())).await; }
        Commands::HttpMethodFuzzer { target } => { run_module_async("http_method_fuzzer", http_method_fuzzer::scan(&target, &common::ScanConfig::default())).await; }
        Commands::WebBackupScanner { target } => { run_module_async("web_backup_scanner", web_backup_scanner::scan(&target, &common::ScanConfig::default())).await; }
        Commands::DomainPermutation { target } => { run_module_async("domain_permutation", domain_permutation::scan(&target, &common::ScanConfig::default())).await; }
        Commands::HttpArchiveScanner { target } => { run_module_async("http_archive_scanner", http_archive_scanner::scan(&target, &common::ScanConfig::default())).await; }
        Commands::All { target, modules } => {
            let start = Instant::now();
            let config: common::ScanConfig = cli.config.as_ref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();

            let selected: HashSet<&str> = modules.as_ref()
                .map(|m| m.split(',').map(|s| s.trim()).collect())
                .unwrap_or_else(|| ALL_MODULES.iter().copied().collect());

            let sel = |name: &str| -> bool { selected.is_empty() || selected.contains(name) };

            let (subs, prts, bann, dns_res, eml, web, crw, sen, sec, wf, soc, crt, vln, cld, who, stls, hh, cve, brch, sto, tf, ad, cb, ss, ps, gd, dzt, crsch, rtrace, caudit, es, asn, jsa, de, wp, dsc, ipr, cd, ebc, mas, gas, fb, csa, ld, smc, eil, di, dws, si, wi, gdk, le, wfd, hmf, wbs, dp, has) = tokio::join!(
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
                web_performance::analyze(&target),
                dns_sec_check::check(&target),
                ip_reputation::check(&target),
                cdn_discovery::discover(&target),
                email_breach_check::check(&target),
                mobile_app_scan::scan(&target),
                graph_api_scan::scan(&target),
                firebase_scanner::scan(&target),
                csp_analyzer::analyze(&target),
                leak_detection::detect(&target),
                social_media_check::scan(&target, &config),
                email_intel::scan(&target, &config),
                dns_intel::scan(&target, &config),
                darkweb_search::scan(&target, &config),
                ssl_intel::scan(&target, &config),
                web_intel::scan(&target, &config),
                google_dorks::scan(&target, &config),
                link_extractor::scan(&target, &config),
                web_form_discovery::scan(&target, &config),
                http_method_fuzzer::scan(&target, &config),
                web_backup_scanner::scan(&target, &config),
                domain_permutation::scan(&target, &config),
                http_archive_scanner::scan(&target, &config),
            );

            let elapsed = start.elapsed().as_millis() as u64;
            let mut result = serde_json::json!({"target": target, "duration_ms": elapsed});

            let insert = |r: &mut serde_json::Value, k: &str, v: serde_json::Value| {
                if !v.is_null() { r[k] = v; }
            };
            if sel("subdomain") { insert(&mut result, "subdomains", safe_json_value(&subs)); }
            if sel("ports") { insert(&mut result, "ports", safe_json_value(&prts)); insert(&mut result, "banners", safe_json_value(&bann)); }
            if sel("dns") { insert(&mut result, "dns", safe_json_value(&dns_res)); }
            if sel("email") { insert(&mut result, "emails", safe_json_value(&eml)); }
            if sel("webtech") { insert(&mut result, "webtech", safe_json_value(&web)); }
            if sel("crawl") { insert(&mut result, "crawl", safe_json_value(&crw)); }
            if sel("sensitive") { insert(&mut result, "sensitive", safe_json_value(&sen)); }
            if sel("secret") { insert(&mut result, "secrets", safe_json_value(&sec)); }
            if sel("waf") { insert(&mut result, "waf", safe_json_value(&wf)); }
            if sel("social") { insert(&mut result, "social", safe_json_value(&soc)); }
            if sel("crtsh") { insert(&mut result, "crtsh", safe_json_value(&crt)); }
            if sel("vuln") { insert(&mut result, "vulns", safe_json_value(&vln)); }
            if sel("cloud") { insert(&mut result, "cloud", safe_json_value(&cld)); }
            if sel("whois") { insert(&mut result, "whois", safe_json_value(&who)); }
            if sel("ssl_tls") { insert(&mut result, "ssl_tls", safe_json_value(&stls)); }
            if sel("http_headers") { insert(&mut result, "http_headers", safe_json_value(&hh)); }
            if sel("cve_search") { insert(&mut result, "cve_search", safe_json_value(&cve)); }
            if sel("breach_check") { insert(&mut result, "breach_check", safe_json_value(&brch)); }
            if sel("subdomain_takeover") { insert(&mut result, "subdomain_takeover", safe_json_value(&sto)); }
            if sel("tech_fingerprint") { insert(&mut result, "tech_fingerprint", safe_json_value(&tf)); }
            if sel("api_discovery") { insert(&mut result, "api_discovery", safe_json_value(&ad)); }
            if sel("cloud_buckets") { insert(&mut result, "cloud_buckets", safe_json_value(&cb)); }
            if sel("social_search") { insert(&mut result, "social_search", safe_json_value(&ss)); }
            if sel("paste_scan") { insert(&mut result, "paste_scan", safe_json_value(&ps)); }
            if sel("git_discovery") { insert(&mut result, "git_discovery", safe_json_value(&gd)); }
            if sel("dns_zone_transfer") { insert(&mut result, "dns_zone_transfer", safe_json_value(&dzt)); }
            if sel("cors_check") { insert(&mut result, "cors_check", safe_json_value(&crsch)); }
            if sel("redirect_trace") { insert(&mut result, "redirect_trace", safe_json_value(&rtrace)); }
            if sel("cookie_audit") { insert(&mut result, "cookie_audit", safe_json_value(&caudit)); }
            if sel("email_security") { insert(&mut result, "email_security", safe_json_value(&es)); }
            if sel("asn_network") { insert(&mut result, "asn_network", safe_json_value(&asn)); }
            if sel("js_analysis") { insert(&mut result, "js_analysis", safe_json_value(&jsa)); }
            if sel("dir_enum") { insert(&mut result, "dir_enum", safe_json_value(&de)); }
            if sel("web_performance") { insert(&mut result, "web_performance", safe_json_value(&wp)); }
            if sel("dns_sec_check") { insert(&mut result, "dns_sec_check", safe_json_value(&dsc)); }
            if sel("ip_reputation") { insert(&mut result, "ip_reputation", safe_json_value(&ipr)); }
            if sel("cdn_discovery") { insert(&mut result, "cdn_discovery", safe_json_value(&cd)); }
            if sel("email_breach_check") { insert(&mut result, "email_breach_check", safe_json_value(&ebc)); }
            if sel("mobile_app_scan") { insert(&mut result, "mobile_app_scan", safe_json_value(&mas)); }
            if sel("graph_api_scan") { insert(&mut result, "graph_api_scan", safe_json_value(&gas)); }
            if sel("firebase_scanner") { insert(&mut result, "firebase_scanner", safe_json_value(&fb)); }
            if sel("csp_analyzer") { insert(&mut result, "csp_analyzer", safe_json_value(&csa)); }
            if sel("leak_detection") { insert(&mut result, "leak_detection", safe_json_value(&ld)); }
            if sel("social_media_check") { insert(&mut result, "social_media_check", safe_json_value(&smc)); }
            if sel("email_intel") { insert(&mut result, "email_intel", safe_json_value(&eil)); }
            if sel("dns_intel") { insert(&mut result, "dns_intel", safe_json_value(&di)); }
            if sel("darkweb_search") { insert(&mut result, "darkweb_search", safe_json_value(&dws)); }
            if sel("ssl_intel") { insert(&mut result, "ssl_intel", safe_json_value(&si)); }
            if sel("web_intel") { insert(&mut result, "web_intel", safe_json_value(&wi)); }
            if sel("google_dorks") { insert(&mut result, "google_dorks", safe_json_value(&gdk)); }
            if sel("link_extractor") { insert(&mut result, "link_extractor", safe_json_value(&le)); }
            if sel("web_form_discovery") { insert(&mut result, "web_form_discovery", safe_json_value(&wfd)); }
            if sel("http_method_fuzzer") { insert(&mut result, "http_method_fuzzer", safe_json_value(&hmf)); }
            if sel("web_backup_scanner") { insert(&mut result, "web_backup_scanner", safe_json_value(&wbs)); }
            if sel("domain_permutation") { insert(&mut result, "domain_permutation", safe_json_value(&dp)); }
            if sel("http_archive_scanner") { insert(&mut result, "http_archive_scanner", safe_json_value(&has)); }

            if progress_enabled() {
                emit("progress", "all", "done");
                println!("{}", serde_json::json!({"event": "complete", "data": result}));
            } else {
                println!("{}", safe_json(&result));
            }
        }
    }
}
