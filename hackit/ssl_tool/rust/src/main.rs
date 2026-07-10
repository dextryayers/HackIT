mod types;
mod analyzer;
mod cert;
mod cipher;
mod vuln;
mod tls_sim;
mod crypto;
mod dns;
mod http;
mod port;
mod report;

use clap::Parser;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "worker_rs", version = "3.0.0")]
struct Args {
    #[arg(long = "json")]
    json: bool,

    #[arg(long = "host", short = 'H')]
    host: Option<String>,

    #[arg(long = "port", short = 'p', default_value = "443")]
    port: u16,

    #[arg(long = "timeout", short = 't', default_value = "15")]
    timeout: u16,

    #[arg(long = "full")]
    full: bool,

    #[arg(long = "output", short = 'o')]
    output: Option<String>,
}

fn main() {
    let args = Args::parse();

    if let Some(host) = args.host {
        run_flag_mode(&host, args.port, args.timeout, args.full, args.output);
    } else {
        eprintln!("Usage: worker_rs --json --host <host> [--port 443] [--timeout 15] [--full] [--output file.json]");
        std::process::exit(1);
    }
}

fn run_flag_mode(host: &str, port: u16, timeout: u16, full: bool, output: Option<String>) {
    let start = Instant::now();
    let result = analyzer::analyze(host, port, timeout, full);
    let elapsed = start.elapsed().as_millis() as u64;

    let mut scan_result = result;
    scan_result.duration_ms = elapsed;

    let json = serde_json::to_string_pretty(&scan_result).unwrap_or_else(|e| {
        format!("{{\"error\":\"JSON serialization failed: {}\"}}", e)
    });
    println!("{}", json);

    if let Some(path) = output {
        if let Err(e) = std::fs::write(&path, &json) {
            eprintln!("[!] Failed to write output: {}", e);
        }
    }
}
