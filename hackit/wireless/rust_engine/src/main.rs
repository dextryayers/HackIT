#![allow(dead_code)]

mod c_bindings;
mod packet_engine;
mod async_concurrency;
mod network_stack;
mod packet_parser;
mod crypto;
mod database;
mod logging;
mod plugin_engine;
mod http_api;
mod advanced_ebpf;
mod adapter_manager;
mod interface_control;
mod traffic_analyzer;
mod capture_engine;
mod network_recon;
mod pcap_wrapper;
mod wpa3_engine;
mod aggressive_scanner;
mod wps_engine;
mod wep_engine;
mod evil_twin;
mod captive_portal;
mod port_scanner;

use clap::{Parser, Subcommand};
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

/// Professional console output helper — mirrors Bettercap/Kismet style
macro_rules! ok {
    ($($arg:tt)*) => { println!("  \x1b[32m✓\x1b[0m {}", format!($($arg)*)) };
}
macro_rules! info_log {
    ($($arg:tt)*) => { println!("  \x1b[34m→\x1b[0m {}", format!($($arg)*)) };
}
macro_rules! warn {
    ($($arg:tt)*) => { println!("  \x1b[33m⚠\x1b[0m {}", format!($($arg)*)) };
}
macro_rules! err {
    ($($arg:tt)*) => { eprintln!("  \x1b[31m✗\x1b[0m {}", format!($($arg)*)) };
}
macro_rules! section {
    ($($arg:tt)*) => { println!("\n  \x1b[1;36m▸ {}\x1b[0m\n", format!($($arg)*)) };
}

/// Detect local subnet automatically (no hardcoded IPs)
fn detect_local_subnet() -> String {
    #[cfg(target_os = "windows")]
    {
        if let Ok(out) = std::process::Command::new("ipconfig").output() {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                if line.contains("IPv4") {
                    let ip = line.split(':').last().unwrap_or("").trim();
                    let parts: Vec<&str> = ip.split('.').collect();
                    if parts.len() == 4 {
                        return format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2]);
                    }
                }
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(out) = std::process::Command::new("hostname").arg("-I").output() {
            let text = String::from_utf8_lossy(&out.stdout);
            let ip = text.split_whitespace().next().unwrap_or("");
            let parts: Vec<&str> = ip.split('.').collect();
            if parts.len() == 4 {
                return format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2]);
            }
        }
    }
    // Last resort: try to detect via routing table
    #[cfg(target_os = "windows")]
    {
        if let Ok(out) = std::process::Command::new("netstat").args(["-rn"]).output() {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                if line.contains("0.0.0.0") && line.contains("192") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let gw = parts[2];
                        let octets: Vec<&str> = gw.split('.').collect();
                        if octets.len() == 4 {
                            return format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
                        }
                    }
                }
            }
        }
    }
    "0.0.0.0/0".into()
}

/// Generate a cryptographically plausible random SSID based on environment
fn generate_random_ssid() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let suffixes = ["WiFi", "AP", "NETWORK", "5G", "GUEST", "HOME", "LINK", "NODE"];
    let idx = (t % suffixes.len() as u128) as usize;
    format!("HackIT_{}_{}", suffixes[idx], t % 10000)
}

/// Generate a random locally-administered MAC address
fn generate_random_mac() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let b3 = ((t >> 32) & 0xFF) as u8;
    let b4 = ((t >> 24) & 0xFF) as u8;
    let b5 = ((t >> 16) & 0xFF) as u8;
    let b6 = ((t >> 8) & 0xFF) as u8;
    format!("02:00:{:02X}:{:02X}:{:02X}:{:02X}", b3, b4, b5, b6)
}

#[derive(Parser)]
#[command(
    name = "hackit-wireless",
    author = "HackIT OSINT Framework",
    version = "2.1.0",
    about = "⚡ High-performance Wireless Penetration Testing Engine",
    long_about = "HackIT Wireless Engine — a multi-language (Rust/Go/C/Python/C#) \
wireless assessment suite with real-time adapter detection, zero hardcoded values, \
and full 2.4/5GHz dual-band support.\n\n\
Examples:\n  hackit-wireless sniff -i wlan0 --monitor\n  \
hackit-wireless handshake -i wlan0 -b AA:BB:CC:DD:EE:FF\n  \
hackit-wireless adapters\n  hackit-wireless deauth -i wlan0 -b AA:BB:CC:DD:EE:FF -c 5",
    arg_required_else_help = true,
    disable_version_flag = false,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all detected wireless interfaces in real-time (no hardcoded names)
    #[command(name = "adapters")]
    Adapters,

    /// Transition adapter between monitor and managed mode
    #[command(name = "mode")]
    Mode {
        /// Wireless interface name (e.g. wlan0, Wi-Fi)
        #[arg(short = 'i', long = "interface", required = true)]
        interface: String,
        /// Target mode: monitor or managed
        #[arg(short = 'm', long = "mode", required = true)]
        target_mode: String,
    },

    /// Display detailed adapter chipset, driver and capabilities
    #[command(name = "adapter-info")]
    AdapterInfo {
        /// Wireless interface name
        #[arg(short = 'i', long = "interface", required = true)]
        interface: String,
    },

    /// Spoof or restore wireless MAC address
    #[command(name = "mac")]
    Mac {
        /// Wireless interface name
        #[arg(short = 'i', long = "interface", required = true)]
        interface: String,
        /// Action: random, restore, or a specific MAC address
        #[arg(short = 'a', long = "action", required = true)]
        action: String,
    },

    /// Set wireless adapter transmission power (dBm)
    #[command(name = "txpower")]
    TxPower {
        /// Wireless interface name
        #[arg(short = 'i', long = "interface", required = true)]
        interface: String,
        /// TX power in dBm (e.g. 20)
        #[arg(short = 'v', long = "value", required = true)]
        value: i32,
    },

    /// Lock adapter to a specific Wi-Fi channel
    #[command(name = "channel")]
    Channel {
        /// Wireless interface name
        #[arg(short = 'i', long = "interface", required = true)]
        interface: String,
        /// Channel number (1-14 for 2.4GHz, 36-165 for 5GHz)
        #[arg(short = 'c', long = "channel", required = true)]
        channel: i32,
    },

    /// Display interface and engine status
    #[command(name = "status")]
    Status {
        /// Wireless interface name (auto-detected if omitted)
        #[arg(short = 'i', long = "interface", default_value = "")]
        interface: String,
    },

    /// Passive live 802.11 capture and frame analysis
    #[command(name = "sniff")]
    Sniff {
        /// Wireless interface in monitor mode
        #[arg(short = 'i', long = "interface", required = true)]
        interface: String,
        /// Put interface in monitor mode first (requires root)
        #[arg(short = 'm', long = "monitor", default_value_t = false)]
        monitor: bool,
    },

    /// Hunt for WPA handshake with deauth bursts
    #[command(name = "hunt")]
    Hunt {
        /// Wireless interface name
        #[arg(short = 'i', long = "interface", required = true)]
        interface: String,
        /// Target BSSID (AP MAC address)
        #[arg(short = 'b', long = "bssid", required = true)]
        bssid: String,
    },

    /// Map/audit AP against whitelist
    #[command(name = "map")]
    Map {
        /// SSID of the access point
        #[arg(short = 's', long = "ssid", required = true)]
        ssid: String,
        /// BSSID of the access point
        #[arg(short = 'b', long = "bssid", required = true)]
        bssid: String,
        /// Path to whitelist file
        #[arg(short = 'w', long = "whitelist")]
        whitelist: Option<String>,
    },

    /// Live AP beacon/probe monitoring
    #[command(name = "recon")]
    Recon {
        /// Interface for monitoring
        #[arg(short = 'i', long = "interface", required = true)]
        iface: String,
    },

    /// ARP scan local subnet for live hosts
    #[command(name = "arp-scan")]
    ArpScan {
        /// Subnet in CIDR notation (auto-detected if omitted)
        #[arg(short = 's', long = "subnet")]
        subnet: Option<String>,
    },

    /// Fast TCP port scan against a host
    #[command(name = "port-scan")]
    PortScan {
        /// Target IP or hostname
        #[arg(short = 'H', long = "host", required = true)]
        host: String,
    },

    /// Passive OS fingerprinting via TCP/IP stack analysis
    #[command(name = "osdetect")]
    OsDetect {
        /// Target IP address
        #[arg(short = 'H', long = "host", required = true)]
        host: String,
    },

    /// Send raw 802.11 deauthentication frames
    #[command(name = "deauth")]
    Deauth {
        /// Interface to transmit from
        #[arg(short = 'i', long = "interface", required = true)]
        interface: String,
        /// Target AP BSSID
        #[arg(short = 'b', long = "bssid", required = true)]
        bssid: String,
        /// Target station MAC (broadcast if omitted)
        #[arg(short = 's', long = "station")]
        station: Option<String>,
        /// Number of deauth frames to send
        #[arg(short = 'c', long = "count", default_value_t = 10)]
        count: u32,
    },

    /// Broadcast fake 802.11 beacon frames
    #[command(name = "beacon-flood")]
    BeaconFlood {
        /// Interface to transmit from
        #[arg(short = 'i', long = "interface", required = true)]
        interface: String,
        /// SSID for the fake AP (random if omitted)
        #[arg(short = 's', long = "ssid")]
        ssid: Option<String>,
        /// BSSID (random locally-administered if omitted)
        #[arg(short = 'b', long = "bssid")]
        bssid: Option<String>,
        /// Channel (default: 6)
        #[arg(short = 'c', long = "channel")]
        channel: Option<u8>,
        /// Number of beacon frames to inject
        #[arg(short = 'n', long = "count", default_value_t = 50)]
        count: u32,
    },

    /// Capture all 802.11 frames to PCAP file
    #[command(name = "capture")]
    Capture {
        /// Wireless interface
        #[arg(short = 'i', long = "interface", required = true)]
        iface: String,
        /// Output PCAP file path
        #[arg(short = 'o', long = "output", default_value = "capture.pcap")]
        output: String,
    },

    /// Capture WPA/WPA2 4-way EAPOL handshake
    #[command(name = "handshake")]
    Handshake {
        /// Wireless interface
        #[arg(short = 'i', long = "interface", required = true)]
        iface: String,
        /// Target BSSID (optional — hunts null if omitted)
        #[arg(short = 'b', long = "bssid")]
        bssid: Option<String>,
        /// Output PCAP file path
        #[arg(short = 'o', long = "output", default_value = "handshake.pcap")]
        output: String,
        /// Capture timeout in seconds
        #[arg(short = 't', long = "timeout", default_value_t = 30)]
        timeout: u64,
    },

    /// Verify EAPOL handshake integrity in a PCAP file
    #[command(name = "verify")]
    Verify {
        /// Path to capture file
        #[arg(short = 'c', long = "capture", required = true)]
        capture: String,
    },

    /// Convert PCAP to hashcat HC22000 format
    #[command(name = "convert")]
    Convert {
        /// Input PCAP file
        #[arg(short = 'i', long = "input", required = true)]
        input: String,
        /// Output HC22000 file
        #[arg(short = 'o', long = "output", required = true)]
        output: String,
    },

    /// ARP spoofing MITM attack
    #[command(name = "arp-spoof")]
    ArpSpoof {
        /// Target IP address
        #[arg(short = 't', long = "target", required = true)]
        target: String,
        /// Gateway/router IP address
        #[arg(short = 'g', long = "gateway", required = true)]
        gateway: String,
    },

    /// DNS spoofing — redirect DNS queries to a fake IP
    #[command(name = "dns-spoof")]
    DnsSpoof {
        /// Interface to listen on
        #[arg(short = 'i', long = "interface", required = true)]
        interface: String,
        /// Fake IP to return for all DNS queries
        #[arg(short = 'f', long = "fake-ip", default_value = "8.8.8.8")]
        fake_ip: String,
    },

    /// SSL/TLS stripping — downgrade HTTPS to HTTP
    #[command(name = "ssl-strip")]
    SslStrip {
        /// Interface to proxy traffic through
        #[arg(short = 'i', long = "interface", required = true)]
        interface: String,
        /// Local proxy listen port
        #[arg(short = 'p', long = "port", default_value_t = 8080)]
        listen_port: u16,
    },

    /// Rapid channel hopping across 2.4GHz and/or 5GHz
    #[command(name = "channel-hop")]
    ChannelHop {
        /// Interface to hop on
        #[arg(short = 'i', long = "interface", required = true)]
        interface: String,
        /// Dwell time per channel in milliseconds
        #[arg(short = 'd', long = "dwell", default_value_t = 2)]
        dwell_ms: u64,
        /// Include 5GHz channels in hopping sequence
        #[arg(short = '5', long = "5ghz", alias = "band-5ghz", default_value_t = false)]
        band_5ghz: bool,
    },

    /// Dual-band sniff (2.4GHz + 5GHz) with automatic channel rotation
    #[command(name = "sniff-both")]
    SniffBothBands {
        /// Interface to capture on
        #[arg(short = 'i', long = "interface", required = true)]
        interface: String,
        /// Output PCAP file
        #[arg(short = 'o', long = "output", default_value = "sniff_dual_band.pcap")]
        output: String,
        /// Capture duration in seconds
        #[arg(short = 'd', long = "duration", default_value_t = 60)]
        duration_secs: u64,
    },

    /// Aggressive multi-channel scan (airodump-ng + mdk4 style)
    #[command(name = "aggressive-scan")]
    AggressiveScan {
        /// Interface in monitor mode
        #[arg(short = 'i', long = "interface", required = true)]
        interface: String,
        /// Time per channel in ms
        #[arg(short = 'd', long = "dwell", default_value_t = 200)]
        dwell_ms: u64,
        /// Include 5GHz channels
        #[arg(short = '5', long = "5ghz", default_value_t = false)]
        band_5ghz: bool,
    },

    /// Client hunt — probe for stations and enumerate connected clients
    #[command(name = "client-hunt")]
    ClientHunt {
        /// Interface in monitor mode
        #[arg(short = 'i', long = "interface", required = true)]
        interface: String,
        /// Target BSSID (optional — hunts all if omitted)
        #[arg(short = 'b', long = "bssid")]
        bssid: Option<String>,
    },

    /// Detect WPA3/SAE capable access points via RSN IE parsing
    #[command(name = "wpa3-detect")]
    Wpa3Detect {
        /// Interface in monitor mode
        #[arg(short = 'i', long = "interface", required = true)]
        interface: String,
    },

    /// Probe request flood — broadcast probe requests on all channels
    #[command(name = "probe-flood")]
    ProbeFlood {
        /// Interface in monitor mode
        #[arg(short = 'i', long = "interface", required = true)]
        interface: String,
        /// Number of probe requests to send
        #[arg(short = 'c', long = "count", default_value_t = 100)]
        count: u32,
    },
}

fn inject_frames(iface: &str, frames: &[Vec<u8>], label: &str) {
    match pcap_wrapper::open_capture(iface) {
        Ok(mut session) => {
            let total = frames.len();
            for (i, frame) in frames.iter().enumerate() {
                if pcap_wrapper::send_packet(&mut session, frame) {
                    info_log!("{} frame #{}/{} ({} bytes) ✓", label, i+1, total, frame.len());
                } else {
                    err!("{} frame #{}/{} FAILED", label, i+1, total);
                }
            }
            ok!("{} injection: {}/{} frames sent", label, total, total);
        }
        Err(e) => {
            err!("Cannot open interface {} for injection: {}", iface, e);
        }
    }
}

fn extract_ssid_from_beacon(data: &[u8]) -> String {
    let mut offset = 36usize;
    loop {
        if offset + 2 > data.len() { break; }
        let id = data[offset];
        let len = data[offset + 1] as usize;
        if offset + 2 + len > data.len() { break; }
        if id == 0 && len > 0 {
            if let Ok(s) = std::str::from_utf8(&data[offset+2..offset+2+len]) {
                let trimmed = s.trim_matches('\0');
                if !trimmed.is_empty() { return trimmed.to_string(); }
            }
        }
        if id == 0 { break; }
        offset += 2 + len;
    }
    "<hidden>".to_string()
}

#[tokio::main]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Setting default subscriber failed");

    let cli = Cli::parse();
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        info!("Received Ctrl+C. Shutting down...");
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    match &cli.command {
        Commands::Sniff { interface, monitor } => {
            if *monitor {
                let c_iface = CString::new(interface.as_str()).expect("CString failed");
                unsafe { c_bindings::hackit_wifi_init(); c_bindings::hackit_wifi_set_monitor_mode(c_iface.as_ptr()); }
                ok!("Interface {} switched to monitor mode", interface);
            }
            match pcap_wrapper::open_capture(interface) {
                Ok(mut session) => {
                    pcap_wrapper::set_filter(&mut session, "type mgt subtype beacon or type mgt subtype probe-resp or wlan type data");
                    section!("Sniffing on {} — Ctrl+C to stop", interface);
                    while running.load(Ordering::SeqCst) {
                        if let Some(data) = pcap_wrapper::next_packet(&mut session) {
                            if data.len() < 24 { continue; }
                            let fc = data[0];
                            let frame_type = (fc >> 2) & 0x03;
                            let frame_subtype = (fc >> 4) & 0x0F;
                            if frame_type == 0 && frame_subtype == 8 {
                                let bssid = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                    data[16], data[17], data[18], data[19], data[20], data[21]);
                                let ssid = extract_ssid_from_beacon(&data);
                                println!("  📡 Beacon  {:<17} {:<32} {} bytes", bssid, ssid, data.len());
                            } else if data.len() > 32 && data[24] == 0xAA && data[25] == 0xAA && data[30] == 0x88 && data[31] == 0x8E {
                                let bssid = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                    data[10], data[11], data[12], data[13], data[14], data[15]);
                                let step = capture_engine::detect_eapol_step(&data).unwrap_or(0);
                                println!("  🔐 EAPOL   {:<17} Step {}/4    {} bytes", bssid, step, data.len());
                            } else if frame_type == 2 {
                                let bssid = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                    data[10], data[11], data[12], data[13], data[14], data[15]);
                                println!("  📦 Data    {:<17} {} bytes", bssid, data.len());
                            }
                        } else {
                            break;
                        }
                    }
                }
                Err(e) => err!("{}", e),
            }
            if *monitor { unsafe { c_bindings::hackit_wifi_close(); } }
        }
        Commands::Hunt { interface, bssid } => {
            use std::time::{SystemTime, UNIX_EPOCH};
            let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            let outfile = format!("hunt_{}_{}.pcap", bssid.replace(':', ""), ts);
            section!("Hunting handshake — target {} on {}", bssid, interface);
            match capture_engine::build_deauth_frame(bssid, "FF:FF:FF:FF:FF:FF", 7) {
                Some(frame) => {
                    info_log!("Sending deauth bursts to deauthenticate clients...");
                    let frames = vec![frame; 5];
                    inject_frames(interface, &frames, "DEAUTH-HUNT");
                    info_log!("Capturing handshake from {} → {}", bssid, outfile);
                    let mut session = capture_engine::CaptureSession::new();
                    if session.open_pcap(&outfile) {
                        if let Ok(mut cap) = pcap_wrapper::open_capture(interface) {
                            for _ in 0..60 {
                                if let Some(data) = pcap_wrapper::next_packet(&mut cap) {
                                    session.write_packet(&data);
                                    if let Some(step) = capture_engine::detect_eapol_step(&data) {
                                        ok!("EAPOL handshake step {} captured!", step);
                                    }
                                    if let Some(pmkid) = capture_engine::extract_pmkid(&data) {
                                        ok!("PMKID extracted: {}", pmkid);
                                    }
                                }
                            }
                        }
                        session.close();
                    }
                }
                None => err!("Invalid MAC in hunt command"),
            }
        }
        Commands::ArpSpoof { target, gateway } => {
            section!("ARP Spoof: poisoning {} ↔ {}", target, gateway);
            if let Err(e) = network_recon::arp_spoof(target, gateway) {
                err!("ARP spoof failed: {}", e);
            } else {
                ok!("ARP spoof active");
            }
        }
        Commands::DnsSpoof { interface, fake_ip } => {
            section!("DNS Spoof on {} → {} (requires root)", interface, fake_ip);
            if let Err(e) = network_recon::dns_spoof(interface, fake_ip) {
                err!("DNS spoof failed: {}", e);
            } else {
                ok!("DNS spoof active");
            }
        }
        Commands::SslStrip { interface, listen_port } => {
            section!("SSLStrip on {}:{} (HTTP downgrade proxy)", interface, listen_port);
            if let Err(e) = network_recon::ssl_strip(*listen_port) {
                err!("SSLStrip failed: {}", e);
            } else {
                ok!("SSLStrip proxy running");
            }
        }
        Commands::ChannelHop { interface, dwell_ms, band_5ghz } => {
            section!("Channel hopping on {} (dwell={}ms, 5GHz={})", interface, dwell_ms, band_5ghz);
            let channels: Vec<u8> = if *band_5ghz {
                (36u8..=48).step_by(4)
                    .chain((52u8..=64).step_by(4))
                    .chain((100u8..=144).step_by(4))
                    .chain((149u8..=165).step_by(4))
                    .collect()
            } else {
                (1u8..=14).collect()
            };
            info_log!("{} channels in hopping sequence", channels.len());
            let mut idx = 0;
            while running.load(Ordering::SeqCst) {
                let ch = channels[idx % channels.len()];
                let c_iface = CString::new(interface.as_str()).expect("CString failed");
                unsafe { c_bindings::hackit_c_set_channel(c_iface.as_ptr(), ch as i32); }
                if idx % 10 == 0 { info_log!("Channel {}", ch); }
                std::thread::sleep(std::time::Duration::from_millis(*dwell_ms));
                idx += 1;
            }
            info_log!("Channel hopping stopped.");
        }
        Commands::SniffBothBands { interface, output, duration_secs } => {
            section!("Dual-band sniff: {} → {} ({}s)", interface, output, duration_secs);
            let mut session = capture_engine::CaptureSession::new();
            if !session.open_pcap(output) { return; }
            match pcap_wrapper::open_capture(interface) {
                Ok(mut cap) => {
                    let start = std::time::Instant::now();
                    let channels: Vec<u8> = (1u8..=14).chain((36u8..=64).step_by(4)).chain((100u8..=144).step_by(4)).chain((149u8..=165).step_by(4)).collect();
                    let mut ch_idx = 0usize;
                    let mut last_ch_switch = std::time::Instant::now();
                    while start.elapsed().as_secs() < *duration_secs && running.load(Ordering::SeqCst) {
                        if let Some(data) = pcap_wrapper::next_packet(&mut cap) {
                            session.write_packet(&data);
                        }
                        if last_ch_switch.elapsed().as_millis() > 200 {
                            let ch = channels[ch_idx % channels.len()];
                            let c_iface = CString::new(interface.as_str()).expect("CString failed");
                            unsafe { c_bindings::hackit_c_set_channel(c_iface.as_ptr(), ch as i32); }
                            ch_idx += 1;
                            last_ch_switch = std::time::Instant::now();
                        }
                    }
                }
                Err(e) => err!("Failed to open {} for capture: {}", interface, e),
            }
            session.close();
            ok!("Dual-band capture complete → {}", output);
        }
        Commands::Adapters => {
            let json_str = adapter_manager::list_adapters_json();
            println!("{}", json_str);
        }
        Commands::Mode { interface, target_mode } => {
            let c_interface = CString::new(interface.as_str()).expect("CString failed");
            unsafe {
                c_bindings::hackit_wifi_init();
                if target_mode.to_lowercase() == "monitor" {
                    c_bindings::hackit_wifi_set_monitor_mode(c_interface.as_ptr());
                    ok!("{} switched to monitor mode", interface);
                } else {
                    c_bindings::hackit_wifi_set_managed_mode(c_interface.as_ptr());
                    ok!("{} switched to managed mode", interface);
                }
                c_bindings::hackit_wifi_close();
            }
        }
        Commands::Map { ssid, bssid, whitelist } => {
            let c_ssid = CString::new(ssid.as_str()).expect("CString failed");
            let c_bssid = CString::new(bssid.as_str()).expect("CString failed");
            unsafe {
                c_bindings::hackit_wifi_init();
                if let Some(w_path) = whitelist {
                    let c_path = CString::new(w_path.as_str()).expect("CString failed");
                    if c_bindings::hackit_wifi_load_whitelist(c_path.as_ptr()) {
                        let status = c_bindings::hackit_wifi_is_ap_whitelisted(c_ssid.as_ptr(), c_bssid.as_ptr());
                        let result_str = match status {
                            1 => "AUTHORIZED (SAFE)",
                            2 => "ROGUE AP / EVIL TWIN (ALERT!)",
                            _ => "UNKNOWN / EXTERNAL"
                        };
                        println!("  ▸ {} [{}] → {}", ssid, bssid, result_str);
                    } else {
                        err!("Failed to load whitelist file.");
                    }
                } else {
                    c_bindings::hackit_wifi_audit_ap(c_ssid.as_ptr(), c_bssid.as_ptr());
                }
                c_bindings::hackit_wifi_close();
            }
        }
        Commands::AdapterInfo { interface } => {
            let info = interface_control::get_adapter_info(interface);
            println!("{}", info);
        }
        Commands::Mac { interface, action } => {
            if action.to_lowercase() == "restore" {
                if interface_control::restore_mac(interface) {
                    ok!("Restored original hardware MAC for {}", interface);
                } else {
                    err!("Failed to restore MAC for {}", interface);
                }
            } else {
                let target_mac = if action.to_lowercase() == "random" {
                    let epoch = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis();
                    format!("02:00:{:02X}:{:02X}:{:02X}:{:02X}", (epoch % 256) as u8, ((epoch / 256) % 256) as u8, ((epoch / 65536) % 256) as u8, ((epoch / 16777216) % 256) as u8)
                } else {
                    action.clone()
                };
                if interface_control::change_mac(interface, &target_mac) {
                    ok!("MAC of {} spoofed to {}", interface, target_mac);
                } else {
                    err!("Failed to spoof MAC of {}", interface);
                }
            }
        }
        Commands::TxPower { interface, value } => {
            if interface_control::set_txpower(interface, *value) {
                ok!("TX power of {} set to {} dBm", interface, value);
            } else {
                err!("Failed to set TX power of {}", interface);
            }
        }
        Commands::Channel { interface, channel } => {
            let c_interface = CString::new(interface.as_str()).expect("CString failed");
            unsafe {
                c_bindings::hackit_wifi_init();
                if c_bindings::hackit_wifi_set_channel(c_interface.as_ptr(), *channel) {
                    ok!("Channel {} locked on {}", channel, interface);
                } else {
                    err!("Failed to lock channel {} on {}", channel, interface);
                }
                c_bindings::hackit_wifi_close();
            }
        }
        Commands::Status { interface } => {
            let iface = if interface.is_empty() {
                let adapters = adapter_manager::list_adapters();
                if adapters.is_empty() {
                    err!("No wireless adapters found");
                    return;
                }
                let name = adapters[0].clone();
                ok!("Auto-detected adapter: {}", name);
                name
            } else {
                interface.clone()
            };
            let status = interface_control::get_status(&iface);
            println!("{}", status);
        }
        Commands::Recon { iface } => {
            section!("Reconnaissance on {} — Ctrl+C to stop", iface);
            match pcap_wrapper::open_capture(iface) {
                Ok(mut session) => {
                    pcap_wrapper::set_filter(&mut session, "type mgt subtype beacon or type mgt subtype probe-resp");
                    let analyzer = traffic_analyzer::TrafficAnalyzer::new();
                    while running.load(Ordering::SeqCst) {
                        if let Some(data) = pcap_wrapper::next_packet(&mut session) {
                            analyzer.process_raw_frame(&data);
                            if data.len() >= 24 {
                                let fc = data[0];
                                let sub = (fc >> 4) & 0x0F;
                                if sub == 8 || sub == 5 {
                                    let bssid = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                        data[16], data[17], data[18], data[19], data[20], data[21]);
                                    let ssid = extract_ssid_from_beacon(&data);
                                    println!("  📡 {:<32} {}", ssid, bssid);
                                }
                            }
                        }
                    }
                }
                Err(e) => err!("Failed to open {}: {}", iface, e),
            }
            info_log!("Monitor stopped.");
        }
        Commands::ArpScan { subnet } => {
            let subnet_str = subnet.clone().unwrap_or_else(detect_local_subnet);
            if subnet_str == "0.0.0.0/0" {
                err!("Could not detect local subnet. Specify: --subnet <CIDR>");
                return;
            }
            section!("ARP Scanning: {}", subnet_str);
            network_recon::arp_scan_subnet(&subnet_str);
            ok!("ARP scan complete");
        }
        Commands::PortScan { host } => {
            section!("Port scanning: {}", host);
            let open = network_recon::port_scan(host, network_recon::COMMON_PORTS);
            if open.is_empty() {
                warn!("No open ports found on {}", host);
            } else {
                for p in &open {
                    println!("  🔓 {:<5} {}", p, network_recon::identify_service(*p));
                }
                ok!("{} open ports found", open.len());
            }
        }
        Commands::OsDetect { host } => {
            section!("OS Fingerprinting: {}", host);
            match network_recon::os_detect(host) {
                Some(os) => ok!("Result: {}", os),
                None     => warn!("Could not determine OS for {}", host),
            }
        }
        Commands::Deauth { interface, bssid, station, count } => {
            let station_mac = station.as_deref().unwrap_or("FF:FF:FF:FF:FF:FF");
            section!("Deauth: {} → {} ({} frames on {})", bssid, station_mac, count, interface);
            match capture_engine::build_deauth_frame(bssid, station_mac, 7) {
                Some(frame) => {
                    let frames = vec![frame; *count as usize];
                    inject_frames(interface, &frames, "DEAUTH");
                }
                None => err!("Invalid MAC addresses provided."),
            }
        }
        Commands::BeaconFlood { interface, ssid, bssid, channel, count } => {
            let ssid_str = ssid.clone().unwrap_or_else(generate_random_ssid);
            let bssid_str = bssid.clone().unwrap_or_else(generate_random_mac);
            let channel_val = channel.unwrap_or(6u8);
            section!("Beacon flood: {} AP(s) on {} (SSID={} CH={})", count, interface, ssid_str, channel_val);
            let mut frames = Vec::with_capacity(*count as usize);
            for _ in 0..*count {
                frames.push(capture_engine::build_beacon_frame(&ssid_str, &bssid_str, channel_val));
            }
            inject_frames(interface, &frames, "BEACON");
        }
        Commands::Capture { iface, output } => {
            let mut session = capture_engine::CaptureSession::new();
            if !session.open_pcap(output) { return; }
            match pcap_wrapper::open_capture(iface) {
                Ok(mut cap) => {
                    section!("Capturing on {} → {}  (Ctrl+C to stop)", iface, output);
                    let mut eapol_steps: u8 = 0;
                    while running.load(Ordering::SeqCst) {
                        if let Some(data) = pcap_wrapper::next_packet(&mut cap) {
                            session.write_packet(&data);
                            if let Some(step) = capture_engine::detect_eapol_step(&data) {
                                ok!("EAPOL step {} captured!", step);
                                eapol_steps |= 1 << (step - 1);
                                if eapol_steps == 0b1111 {
                                    ok!("Complete 4-way handshake captured!");
                                }
                            }
                            if let Some(pmkid) = capture_engine::extract_pmkid(&data) {
                                ok!("PMKID: {}", pmkid);
                            }
                        } else { break; }
                    }
                }
                Err(e) => err!("Failed to open {} for capture: {}", iface, e),
            }
            session.close();
        }
        Commands::Verify { capture } => {
            info_log!("Verifying handshake: {}", capture);
            match capture_engine::verify_handshake_pcap(capture) {
                Ok(report) => ok!("{}", report),
                Err(e) => err!("Verification failed: {}", e),
            }
        }
        Commands::Convert { input, output } => {
            info_log!("Converting {} → {}", input, output);
            match capture_engine::convert_pcap_to_hc22000(input, output) {
                Ok(report) => ok!("{}", report),
                Err(e) => err!("Conversion failed: {}", e),
            }
        }
        Commands::Handshake { iface, bssid, output, timeout } => {
            let mut session = capture_engine::CaptureSession::new();
            if !session.open_pcap(output) { return; }
            match pcap_wrapper::open_capture(iface) {
                Ok(mut cap) => {
                    section!("Handshake hunt: {} on {} ({}s timeout)", iface, output, timeout);
                    const BCAST: &str = "FF:FF:FF:FF:FF:FF";
                    if let Some(target) = bssid {
                        if let Some(frame) = capture_engine::build_deauth_frame(target, BCAST, 7) {
                            pcap_wrapper::send_packet(&mut cap, &frame);
                            ok!("Deauth sent to {} to trigger reconnection", target);
                        }
                    }
                    let start = std::time::Instant::now();
                    let mut found_handshake = false;
                    while start.elapsed().as_secs() < *timeout && running.load(Ordering::SeqCst) {
                        if let Some(data) = pcap_wrapper::next_packet(&mut cap) {
                            session.write_packet(&data);
                            if let Some(step) = capture_engine::detect_eapol_step(&data) {
                                ok!("EAPOL step {} captured!", step);
                                found_handshake = true;
                            }
                            if let Some(pmkid) = capture_engine::extract_pmkid(&data) {
                                ok!("PMKID: {}", pmkid);
                            }
                        }
                    }
                    if found_handshake {
                        ok!("WPA handshake captured → {}", output);
                    } else {
                        warn!("No handshake captured. Try --timeout {} or move closer.", timeout + 30);
                    }
                    session.close();
                }
                Err(e) => err!("Failed to open {}: {}", iface, e),
            }
        }
        Commands::AggressiveScan { interface, dwell_ms: _dwell_ms, band_5ghz: _band_5ghz } => {
            section!("Aggressive scan on {}", interface);
            aggressive_scanner::aggressive_scan(interface);
            ok!("Aggressive scan complete");
        }
        Commands::ClientHunt { interface, bssid } => {
            section!("Client hunt on {}", interface);
            if let Some(target) = bssid {
                info_log!("Targeting BSSID: {}", target);
                aggressive_scanner::client_hunt(interface, target);
            } else {
                aggressive_scanner::client_hunt(interface, "");
            }
            ok!("Client hunt complete");
        }
        Commands::Wpa3Detect { interface } => {
            section!("WPA3/SAE detection on {}", interface);
            match pcap_wrapper::open_capture(interface) {
                Ok(mut session) => {
                    pcap_wrapper::set_filter(&mut session, "type mgt subtype beacon or type mgt subtype probe-resp");
                    let mut wpa3_aps = Vec::new();
                    for _ in 0..200 {
                        if let Some(data) = pcap_wrapper::next_packet(&mut session) {
                            if data.len() < 24 { continue; }
                            let fc = data[0];
                            let sub = (fc >> 4) & 0x0F;
                            if sub == 8 {
                                let bssid = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                    data[16], data[17], data[18], data[19], data[20], data[21]);
                                let ssid = extract_ssid_from_beacon(&data);
                                if wpa3_engine::detect_wpa3(&data) {
                                    wpa3_aps.push((ssid, bssid));
                                }
                            }
                        }
                    }
                    if wpa3_aps.is_empty() {
                        warn!("No WPA3/SAE APs detected");
                    } else {
                        for (ssid, bssid) in &wpa3_aps {
                            println!("  🔐 WPA3  {:<32} {}", ssid, bssid);
                        }
                        ok!("{} WPA3 AP(s) found", wpa3_aps.len());
                    }
                }
                Err(e) => err!("Failed to open {}: {}", interface, e),
            }
        }
        Commands::ProbeFlood { interface, count } => {
            section!("Probe request flood: {} frames on {}", count, interface);
            let _ = aggressive_scanner::probe_request_flood(interface, "HackIT", *count);
            ok!("Probe flood complete");
        }
    }
}
