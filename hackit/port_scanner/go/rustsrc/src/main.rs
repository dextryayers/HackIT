use clap::{Parser, Subcommand};
use serde::Serialize;
use std::net::ToSocketAddrs;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

mod scan;
mod syn;
mod os;
mod rate;

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
        #[arg(short, long, default_value = "1-1024")]
        ports: String,
        #[arg(short, long, default_value_t = 500)]
        workers: usize,
        #[arg(short, long, default_value_t = 1500)]
        timeout: u64,
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
        #[arg(short, long, default_value = "1-1024")]
        ports: String,
        #[arg(short, long, default_value_t = 500)]
        workers: usize,
        #[arg(short, long, default_value_t = 1500)]
        timeout: u64,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { target, ports, workers, timeout, json } => {
            scan::run_scan(&target, &ports, workers, timeout, json).await;
        }
        Commands::Syn { target, ports, rate, json } => {
            syn::run_syn_scan(&target, &ports, rate, json);
        }
        Commands::Os { target, json } => {
            os::run_os_detect(&target, json);
        }
        Commands::All { target, ports, workers, timeout, json } => {
            println!("[RUST] Running all scans against {}", target);
            let start = Instant::now();
            // Phase 1: TCP scan + service
            scan::run_scan(&target, &ports, workers, timeout, json).await;
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
