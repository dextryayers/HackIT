use clap::{Parser, Subcommand};
use std::time::Instant;

mod banner;
mod scan;
mod syn;
mod os;
mod rate;
mod dns_resolver;
mod ping_sweep;
mod http_probe;
mod tls_scanner;
mod script_engine;
mod vuln_check;

#[derive(Parser)]
#[command(name = "portstorm-rust", version = "3.0.0", about = "PortStorm Rust Engine — mass async scanner")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// TCP connect scan with banner grab + service detection
    Scan {
        target: String,
        #[arg(short, long, default_value = "top100")]
        ports: String,
        #[arg(short, long, default_value_t = 500)]
        workers: usize,
        #[arg(short, long, default_value_t = 1500)]
        timeout: u64,
        /// Retries for inconclusive (filtered) ports
        #[arg(long, default_value_t = 1)]
        retries: u32,
        /// Delay between port dispatches, milliseconds
        #[arg(long, default_value_t = 0)]
        delay: u64,
        /// Shuffle port order
        #[arg(long, default_value_t = false)]
        randomize: bool,
        /// Skip banner probing (fast state-only scan)
        #[arg(long, default_value_t = false)]
        no_banner: bool,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// SYN scan (requires root)
    Syn {
        target: String,
        #[arg(short, long, default_value = "1-1024")]
        ports: String,
        #[arg(short, long, default_value_t = 100_000)]
        rate: u64,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// OS fingerprint
    Os {
        target: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Run all scans (TCP + SYN + OS + service)
    All {
        target: String,
        #[arg(short, long, default_value = "top100")]
        ports: String,
        #[arg(short, long, default_value_t = 500)]
        workers: usize,
        #[arg(short, long, default_value_t = 1500)]
        timeout: u64,
        #[arg(long, default_value_t = 1)]
        retries: u32,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { target, ports, workers, timeout, retries, delay, randomize, no_banner, json } => {
            let opts = scan::ScanOptions {
                workers,
                timeout_ms: timeout,
                retries,
                delay_ms: delay,
                randomize,
                banners: !no_banner,
            };
            scan::run_scan(&target, &ports, &opts, json).await;
        }
        Commands::Syn { target, ports, rate, json } => {
            syn::run_syn_scan(&target, &ports, rate, json);
        }
        Commands::Os { target, json } => {
            os::run_os_detect(&target, json);
        }
        Commands::All { target, ports, workers, timeout, retries, json } => {
            println!("[RUST] Running all scans against {}", target);
            let start = Instant::now();
            // Phase 1: TCP scan + service
            let opts = scan::ScanOptions { workers, timeout_ms: timeout, retries, ..Default::default() };
            scan::run_scan(&target, &ports, &opts, json).await;
            // Phase 2: OS detect
            os::run_os_detect(&target, json);
            // Phase 3: SYN scan (if root)
            syn::run_syn_scan(&target, &ports, 100_000, json);
            let elapsed = start.elapsed();
            if !json {
                println!("\n[RUST] All scans completed in {:?}", elapsed);
            }
        }
    }
}
