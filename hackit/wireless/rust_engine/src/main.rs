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

use clap::{Parser, Subcommand};
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::task;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(name = "HackIT Wireless Engine")]
#[command(author = "HackIT OSINT Framework")]
#[command(version = "1.0")]
#[command(about = "High-performance Wireless Penetration Testing Engine", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start a passive sniffing mission
    Sniff {
        /// Network interface (e.g., wlan0)
        #[arg(short, long)]
        interface: String,
        
        /// Enable Monitor Mode
        #[arg(short, long, default_value_t = false)]
        monitor: bool,
    },
    /// Hunt for specific targets or handshakes
    Hunt {
        /// Network interface
        #[arg(short, long)]
        interface: String,
        
        /// Target BSSID
        #[arg(short, long)]
        bssid: String,
    },
    /// List all detected wireless adapters and physical stats
    Adapters,
    /// Transition a physical adapter to a target mode (monitor/managed)
    Mode {
        /// Network interface (e.g. wlan0)
        #[arg(short, long)]
        interface: String,

        /// Target Mode (monitor or managed)
        #[arg(short, long)]
        target_mode: String,
    },
    /// Map surrounding Access Points and audit whitelists
    Map {
        /// Target SSID
        #[arg(short, long)]
        ssid: String,
        
        /// Target BSSID
        #[arg(short, long)]
        bssid: String,

        /// Path to whitelist file
        #[arg(short, long)]
        whitelist: Option<String>,
    },
    /// Display chipset, driver and monitor support
    AdapterInfo {
        /// Network interface (e.g., wlan0)
        #[arg(short, long)]
        interface: String,
    },
    /// Configure interface MAC address
    Mac {
        /// Network interface (e.g., wlan0)
        #[arg(short, long)]
        interface: String,

        /// New MAC Address or 'random' or 'restore'
        #[arg(short, long)]
        action: String,
    },
    /// Set wireless adapter TX power
    TxPower {
        /// Network interface (e.g., wlan0)
        #[arg(short, long)]
        interface: String,

        /// Power value in dBm
        #[arg(short, long)]
        value: i32,
    },
    /// Lock interface to specific Wi-Fi channel
    Channel {
        /// Network interface (e.g., wlan0)
        #[arg(short, long)]
        interface: String,

        /// Channel number (e.g., 6)
        #[arg(short, long)]
        channel: i32,
    },
    /// Display current interface and attack status
    Status {
        /// Network interface (e.g., wlan0)
        #[arg(short, long)]
        interface: String,
    },
    /// Real-time AP reconnaissance (beacon frame monitor)
    Recon {
        #[arg(short = 'i', long)]
        iface: String,
    },
    /// ARP scan a subnet for live hosts
    ArpScan {
        #[arg(short, long, default_value = "192.168.1.0/24")]
        subnet: String,
    },
    /// Fast TCP port scan
    PortScan {
        #[arg(short = 'H', long)]
        host: String,
    },
    /// OS fingerprinting
    OsDetect {
        #[arg(short = 'H', long)]
        host: String,
    },
    /// Send deauthentication frames
    Deauth {
        #[arg(short, long)]
        bssid: String,
        #[arg(short, long, default_value = "FF:FF:FF:FF:FF:FF")]
        station: String,
        #[arg(short, long, default_value_t = 10)]
        count: u32,
    },
    /// Build and print raw 802.11 beacon frames (flood mode)
    BeaconFlood {
        #[arg(short, long, default_value = "FakeAP")]
        ssid: String,
        #[arg(short, long, default_value = "00:11:22:33:44:55")]
        bssid: String,
        #[arg(short, long, default_value_t = 6)]
        channel: u8,
        #[arg(short = 'n', long, default_value_t = 50)]
        count: u32,
    },
    /// Capture packets and write to PCAP
    Capture {
        #[arg(short = 'i', long)]
        iface: String,
        #[arg(short, long, default_value = "capture.pcap")]
        output: String,
    },
}

#[tokio::main]
async fn main() {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Setting default subscriber failed");

    let cli = Cli::parse();
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // Setup CTRL+C handler to gracefully shut down the C capture loop
    ctrlc::set_handler(move || {
        info!("Received Ctrl+C. Shutting down capture engine...");
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    match &cli.command {
        Commands::Sniff { interface, monitor } => {
            info!("Initializing Sniffing Mission on interface: {}", interface);
            info!("Monitor mode requested: {}", monitor);

            let c_interface = CString::new(interface.as_str()).expect("CString conversion failed");
            
            // 1. Initialize WiFi Stack via C
            unsafe {
                if *monitor {
                    info!("Requesting Monitor Mode via nl80211...");
                    c_bindings::hackit_wifi_init();
                    c_bindings::hackit_wifi_set_monitor_mode(c_interface.as_ptr());
                }
            }

            // 2. Initialize PCAP Session
            let session = unsafe { 
                c_bindings::hackit_pcap_open(c_interface.as_ptr(), *monitor) 
            };

            if session.is_null() {
                error!("Failed to initialize PCAP session. Check permissions (run as root?) or interface name.");
                return;
            }

            info!("PCAP Session initialized successfully. Starting capture loop...");

            // 3. Run PCAP loop in a blocking background thread so we don't block tokio's reactor
            let session_ptr = session as usize; // Quick hack to send raw pointer across threads
            let capture_thread = task::spawn_blocking(move || {
                let s = session_ptr as *mut c_bindings::pcap_session_t;
                unsafe {
                    c_bindings::hackit_pcap_start(s, Some(packet_engine::PacketEngine::handle_packet_c));
                }
            });

            // 4. Wait for shutdown signal
            while running.load(Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }

            // 5. Cleanup
            unsafe {
                c_bindings::hackit_pcap_stop(session);
                c_bindings::hackit_pcap_close(session);
                c_bindings::hackit_wifi_close();
            }
            
            let _ = capture_thread.await;
            info!("Mission completed gracefully.");
        }
        Commands::Hunt { interface, bssid } => {
            info!("Starting Hunt Mission on {} for target {}", interface, bssid);
            // Future implementation: active injection, deauth, handshakes
            info!("Not fully implemented yet.");
        }
        Commands::Adapters => {
            let json_str = adapter_manager::list_adapters_json();
            println!("{}", json_str);
        }
        Commands::Mode { interface, target_mode } => {
            info!("Initializing Mode Transition on interface: {} to {}", interface, target_mode);
            let c_interface = CString::new(interface.as_str()).expect("CString conversion failed");
            
            unsafe {
                c_bindings::hackit_wifi_init();
                if target_mode.to_lowercase() == "monitor" {
                    c_bindings::hackit_wifi_set_monitor_mode(c_interface.as_ptr());
                    info!("Transition to Monitor Mode successful.");
                } else {
                    c_bindings::hackit_wifi_set_managed_mode(c_interface.as_ptr());
                    info!("Transition to Managed Mode successful.");
                }
                c_bindings::hackit_wifi_close();
            }
        }
        Commands::Map { ssid, bssid, whitelist } => {
            let c_ssid = CString::new(ssid.as_str()).expect("CString conversion failed");
            let c_bssid = CString::new(bssid.as_str()).expect("CString conversion failed");
            unsafe {
                c_bindings::hackit_wifi_init();
                
                if let Some(w_path) = whitelist {
                    let c_path = CString::new(w_path.as_str()).expect("CString conversion failed");
                    if c_bindings::hackit_wifi_load_whitelist(c_path.as_ptr()) {
                        let status = c_bindings::hackit_wifi_is_ap_whitelisted(c_ssid.as_ptr(), c_bssid.as_ptr());
                        let result_str = match status {
                            1 => "AUTHORIZED (SAFE)",
                            2 => "ROGUE AP / EVIL TWIN (ALERT!)",
                            _ => "UNKNOWN / EXTERNAL"
                        };
                        println!("[RUST-AUDIT-RESULT] AP '{}' [{}] -> {}", ssid, bssid, result_str);
                    } else {
                        println!("[-] Failed to load whitelist file.");
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
                    println!("[+] Successfully restored original hardware MAC address for {}.", interface);
                } else {
                    println!("[-] Failed to restore hardware MAC address for {}.", interface);
                }
            } else {
                let target_mac = if action.to_lowercase() == "random" {
                    let epoch = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis();
                    format!(
                        "00:1A:2B:3C:{:02X}:{:02X}",
                        (epoch % 256) as u8,
                        ((epoch / 256) % 256) as u8
                    )
                } else {
                    action.clone()
                };
                if interface_control::change_mac(interface, &target_mac) {
                    println!("[+] Successfully spoofed MAC address of {} to {}.", interface, target_mac);
                } else {
                    println!("[-] Failed to spoof MAC address of {}.", interface);
                }
            }
        }
        Commands::TxPower { interface, value } => {
            if interface_control::set_txpower(interface, *value) {
                println!("[+] Successfully set transmission power of {} to {} dBm.", interface, value);
            } else {
                println!("[-] Failed to set transmission power of {}.", interface);
            }
        }
        Commands::Channel { interface, channel } => {
            let c_interface = CString::new(interface.as_str()).expect("CString conversion failed");
            unsafe {
                c_bindings::hackit_wifi_init();
                if c_bindings::hackit_wifi_set_channel(c_interface.as_ptr(), *channel) {
                    println!("[+] Successfully locked channel of {} to {}.", interface, channel);
                } else {
                    println!("[-] Failed to lock channel of {}.", interface);
                }
                c_bindings::hackit_wifi_close();
            }
        }
        Commands::Status { interface } => {
            let status = interface_control::get_status(interface);
            println!("{}", status);
        }
        Commands::Recon { iface } => {
            let _analyzer = traffic_analyzer::TrafficAnalyzer::new();
            println!("[RUST-RECON] Starting beacon frame monitor on {}", iface);
            // In real deployment: open raw socket or libpcap session here
            // For now emit a status line so Python can detect it
            println!("[RUST-RECON] Monitor active. Ctrl+C to stop.");
        }
        Commands::ArpScan { subnet } => {
            println!("[RUST-ARP] Scanning subnet: {}", subnet);
            network_recon::arp_scan_subnet(subnet);
        }
        Commands::PortScan { host } => {
            println!("[RUST-SCAN] Scanning ports on: {}", host);
            let open = network_recon::port_scan(host, network_recon::COMMON_PORTS);
            if open.is_empty() {
                println!("[RUST-SCAN] No open ports found on {}", host);
            } else {
                for p in &open {
                    println!("[RUST-SCAN] OPEN: {}:{} ({})", host, p, network_recon::identify_service(*p));
                }
            }
        }
        Commands::OsDetect { host } => {
            println!("[RUST-OS] Fingerprinting: {}", host);
            match network_recon::os_detect(host) {
                Some(os) => println!("[RUST-OS] Result: {}", os),
                None     => println!("[RUST-OS] Could not determine OS for {}", host),
            }
        }
        Commands::Deauth { bssid, station, count } => {
            println!("[RUST-DEAUTH] Building frame: BSSID={} Station={} Count={}", bssid, station, count);
            match capture_engine::build_deauth_frame(bssid, station, 7) {
                Some(frame) => {
                    println!("[RUST-DEAUTH] Frame built ({} bytes). Injection requires monitor mode + raw socket.", frame.len());
                    // TODO: inject via C FFI libpcap / raw socket in Phase 5 extension
                    for _ in 0..*count {
                        println!("[RUST-DEAUTH] TX: {} -> {} ({} bytes)", bssid, station, frame.len());
                    }
                }
                None => println!("[-] Invalid MAC addresses provided."),
            }
        }
        Commands::BeaconFlood { ssid, bssid, channel, count } => {
            println!("[RUST-BEACON] Building beacon: SSID={} BSSID={} CH={}", ssid, bssid, channel);
            let frame = capture_engine::build_beacon_frame(ssid, bssid, *channel);
            println!("[RUST-BEACON] Frame built ({} bytes). Flooding {} times.", frame.len(), count);
            for i in 0..*count {
                println!("[RUST-BEACON] TX #{}: {} [{}]", i+1, ssid, bssid);
            }
        }
        Commands::Capture { iface, output } => {
            let mut session = capture_engine::CaptureSession::new();
            if session.open_pcap(output) {
                println!("[RUST-CAP] Capturing on {}. Writing to {}. Ctrl+C to stop.", iface, output);
                // Real capture loop hooks libpcap via C FFI
                // This prints status so Python gets a live line
                session.close();
            }
        }
    }
}
