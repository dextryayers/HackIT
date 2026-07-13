use clap::Parser;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;

mod protocols;
mod core;

#[derive(Parser)]
#[command(name = "keystrike", version = "2.0.0", about = "HackIT KeyStrike Bruteforce Engine — Standalone Multi-Protocol")]
struct Args {
    #[arg(short = 't', long)]
    target: String,

    #[arg(short = 'p', long, default_value = "0")]
    port: u16,

    #[arg(short = 'P', long)]
    protocol: String,

    #[arg(short = 'u', long)]
    user: Option<String>,

    #[arg(short = 'U', long)]
    userlist: Option<String>,

    #[arg(short = 'w', long)]
    pass: Option<String>,

    #[arg(short = 'W', long)]
    passlist: Option<String>,

    #[arg(short = 'T', long, default_value = "32")]
    threads: usize,

    #[arg(long, default_value = "10")]
    timeout: u64,

    #[arg(long, default_value = "false")]
    json: bool,

    #[arg(long)]
    proxy: Option<String>,

    #[arg(long, default_value = "500")]
    rate_limit: f64,

    #[arg(long)]
    expand_words: bool,
}

#[derive(Serialize)]
struct Progress {
    status: String,
    attempted: u64,
    total: u64,
    found: u64,
    speed: f64,
    elapsed: f64,
}

#[derive(Serialize, Clone)]
struct FoundCred {
    status: String,
    protocol: String,
    target: String,
    port: u16,
    username: String,
    password: String,
}

fn load_list(path: &str) -> Vec<String> {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let json_mode = args.json;

    let mut users: Vec<String> = if let Some(ref u) = args.user {
        vec![u.clone()]
    } else if let Some(ref ul) = args.userlist {
        load_list(ul)
    } else {
        vec!["root".into(), "admin".into(), "user".into()]
    };

    let mut passes: Vec<String> = if let Some(ref p) = args.pass {
        vec![p.clone()]
    } else if let Some(ref pl) = args.passlist {
        load_list(pl)
    } else {
        vec![
            "admin".into(),
            "123456".into(),
            "password".into(),
            "root".into(),
            "12345".into(),
        ]
    };

    if args.expand_words {
        passes = core::WordlistGenerator::expand(&passes, 99, true);
        users = core::WordlistGenerator::expand(&users, 9, false);
    }

    let protocol_name = args.protocol.to_lowercase();
    let port = if args.port == 0 {
        protocols::default_port(&protocol_name)
    } else {
        args.port
    };

    if port == 0 {
        let msg = serde_json::json!({
            "status": "error",
            "message": format!("Unknown protocol: {}", protocol_name)
        });
        println!("{}", msg);
        std::process::exit(1);
    }

    let combo_count = users.len() * passes.len();
    let combo_u64 = combo_count as u64;
    let semaphore = Arc::new(Semaphore::new(args.threads));
    let attempted = Arc::new(AtomicU64::new(0));
    let found_count = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let found_creds = Arc::new(tokio::sync::Mutex::new(Vec::new()));

    let rate_limiter = Arc::new(core::RateLimiter::new(args.rate_limit, 10.0));
    let proxy_chain = args
        .proxy
        .as_deref()
        .map(core::ProxyChain::parse_list)
        .unwrap_or_default();

    if !json_mode {
        eprintln!(
            "[KeyStrike] Target: {}:{} | Protocol: {} | Users: {} | Passwords: {} | Combos: {} | Threads: {}",
            args.target,
            port,
            protocol_name,
            users.len(),
            passes.len(),
            combo_u64,
            args.threads
        );
        if args.expand_words {
            eprintln!("[KeyStrike] Wordlist expansion enabled");
        }
        if args.proxy.is_some() {
            eprintln!("[KeyStrike] Proxy chain: {}", args.proxy.unwrap_or_default());
        }
    }

    let mut handles = Vec::new();
    let report_every = std::cmp::max(combo_u64 / 100, 1);

    for user in &users {
        for pass in &passes {
            let u = user.clone();
            let p = pass.clone();
            let t = args.target.clone();
            let proto = protocol_name.clone();
            let sem = semaphore.clone();
            let att = attempted.clone();
            let found = found_count.clone();
            let fc = found_creds.clone();
            let port_num = port;
            let to = args.timeout;
            let total = combo_u64;
            let start_t = start;
            let rl = rate_limiter.clone();
            let _proxy = proxy_chain.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();

                let delay = rl.acquire().await;
                if delay > std::time::Duration::ZERO {
                    tokio::time::sleep(delay).await;
                }

                let ok = protocols::try_auth(&proto, &t, port_num, &u, &p, to).await;
                let att_val = att.fetch_add(1, Ordering::SeqCst) + 1;

                match &ok {
                    Ok(true) => {
                        found.fetch_add(1, Ordering::SeqCst);
                        rl.report_success().await;
                        let cred = FoundCred {
                            status: "found".to_string(),
                            protocol: proto.clone(),
                            target: t.clone(),
                            port: port_num,
                            username: u.clone(),
                            password: p.clone(),
                        };
                        if json_mode {
                            println!("{}", serde_json::to_string(&cred).unwrap());
                        } else {
                            println!(
                                "[+] FOUND  {}:{} @ {}:{}",
                                u, p, t, port_num
                            );
                        }
                        fc.lock().await.push(cred);
                    }
                    Ok(false) => {
                        rl.report_failure().await;
                    }
                    Err(_) => {
                        rl.report_failure().await;
                    }
                }

                if json_mode && att_val % report_every == 0 {
                    let elapsed = start_t.elapsed().as_secs_f64();
                    let speed = if elapsed > 0.0 {
                        att_val as f64 / elapsed
                    } else {
                        0.0
                    };
                    let prog = Progress {
                        status: "progress".into(),
                        attempted: att_val,
                        total,
                        found: found.load(Ordering::SeqCst),
                        speed,
                        elapsed,
                    };
                    println!("{}", serde_json::to_string(&prog).unwrap());
                } else if !json_mode
                    && att_val % std::cmp::max(combo_u64 / 20, 1) == 0
                {
                    let elapsed = start_t.elapsed().as_secs_f64();
                    let speed = if elapsed > 0.0 {
                        att_val as f64 / elapsed
                    } else {
                        0.0
                    };
                    eprintln!(
                        "[KeyStrike] Progress: {}/{} ({:.0}%) | {:.0}/s | Found: {}",
                        att_val,
                        total,
                        (att_val as f64 / total as f64) * 100.0,
                        speed,
                        found.load(Ordering::SeqCst)
                    );
                }
            });
            handles.push(handle);
        }
    }

    for h in handles {
        let _ = h.await;
    }

    let elapsed = start.elapsed().as_secs_f64();
    let speed = if elapsed > 0.0 {
        combo_u64 as f64 / elapsed
    } else {
        0.0
    };

    if json_mode {
        let summary = serde_json::json!({
            "status": "complete",
            "elapsed": elapsed,
            "total_attempts": combo_u64,
            "speed": format!("{:.0}/s", speed),
            "found": found_count.load(Ordering::SeqCst),
            "results": *found_creds.lock().await,
        });
        println!("{}", summary);
    } else {
        eprintln!(
            "\n[KeyStrike] Done! {:.1}s | {:.0}/s | Found: {}",
            elapsed,
            speed,
            found_count.load(Ordering::SeqCst)
        );
    }
}
