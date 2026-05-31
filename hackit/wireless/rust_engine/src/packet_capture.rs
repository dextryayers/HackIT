use pcap::{Capture, Device};
use serde::Serialize;
use std::time::Duration;
use tracing::{error, info};

#[derive(Serialize)]
pub struct SniffedPacket {
    pub event: String,
    pub bssid: String,
    pub ssid: String,
    pub size: usize,
}

pub fn start_live_sniffing(iface: &str) {
    info!("Initializing Live Packet Sniffing on {}", iface);

    let device: Device = match Device::list() {
        Ok(devices) => devices
            .into_iter()
            .find(|d| d.name == iface)
            .unwrap_or_else(|| Device::lookup().expect("Failed to lookup").expect("No device found")),
        Err(_) => {
            error!("Could not list pcap devices. Are you running as root/Administrator?");
            return;
        }
    };

    let mut cap = match Capture::from_device(device)
        .expect("Capture device error")
        .promisc(true)
        .snaplen(5000)
        .timeout(200)
        .open()
    {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to open device {}: {:?}", iface, e);
            return;
        }
    };

    // Filter to only capture 802.11 beacons and probes (if supported by adapter mode)
    if let Err(e) = cap.filter("type mgt subtype beacon", true) {
        info!("BPF Filter warning (may not be supported on windows without winpcap): {:?}", e);
    }

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                let size = packet.header.len as usize;
                
                // Very basic fallback parsing to JSON.
                // A complete parsing logic for 802.11 is complex without radiotap unpacker,
                // but we will output a JSON line so python can stream it natively.
                let data = SniffedPacket {
                    event: "beacon".to_string(),
                    bssid: extract_mac(&packet.data, 10),
                    ssid: extract_ssid(&packet.data).unwrap_or_else(|| "Hidden".to_string()),
                    size,
                };

                // Print to stdout as JSON for Python to consume
                if let Ok(json_line) = serde_json::to_string(&data) {
                    println!("{}", json_line);
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                continue;
            }
            Err(e) => {
                error!("Packet capture error: {:?}", e);
                break;
            }
        }
    }
}

// Dummy extractors for illustration - real 802.11 parsing requires skipping radiotap.
fn extract_mac(data: &[u8], offset: usize) -> String {
    if data.len() >= offset + 6 {
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3], data[offset + 4], data[offset + 5]
        )
    } else {
        "??:??:??:??:??:??".to_string()
    }
}

fn extract_ssid(data: &[u8]) -> Option<String> {
    if data.len() > 38 && data[36] == 0 {
        let ssid_len = data[37] as usize;
        if data.len() >= 38 + ssid_len {
            return String::from_utf8(data[38..38 + ssid_len].to_vec()).ok();
        }
    }
    None
}
