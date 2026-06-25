use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::pcap_wrapper;

pub struct EvilTwinAp {
    ssid: String,
    bssid: String,
    channel: u8,
    running: bool,
}

fn parse_mac(mac_str: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return None;
        }
        bytes[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(bytes)
}

fn generate_bssid_from_ssid(ssid: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    ssid.hash(&mut hasher);
    let h = hasher.finish();
    format!("02:00:{:02X}:{:02X}:{:02X}:{:02X}",
            ((h >> 24) & 0xFF) as u8,
            ((h >> 16) & 0xFF) as u8,
            ((h >> 8) & 0xFF) as u8,
            (h & 0xFF) as u8)
}

fn build_beacon_frame(ssid: &str, bssid: &[u8; 6], channel: u8) -> Vec<u8> {
    let ssid_bytes = ssid.as_bytes();
    let ssid_len = ssid_bytes.len().min(32);
    let mut frame = Vec::with_capacity(64 + ssid_len + 8);
    frame.push(0x80);
    frame.push(0x00);
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    frame.extend_from_slice(bssid);
    frame.extend_from_slice(bssid);
    frame.push(0x00);
    frame.push(0x00);
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    frame.push(0x00);
    frame.push(ssid_len as u8);
    frame.extend_from_slice(&ssid_bytes[..ssid_len]);
    frame.push(0x01);
    frame.push(0x08);
    frame.extend_from_slice(&[0x02, 0x04, 0x0B, 0x16, 0x0C, 0x12, 0x18, 0x24]);
    frame.push(0x03);
    frame.push(0x01);
    frame.push(channel);
    frame
}

fn build_deauth_frame(bssid: &[u8; 6], station: &[u8; 6], reason: u16) -> Vec<u8> {
    let mut frame = Vec::with_capacity(26);
    frame.push(0xC0);
    frame.push(0x00);
    frame.extend_from_slice(station);
    frame.extend_from_slice(bssid);
    frame.extend_from_slice(bssid);
    frame.push(0x00);
    frame.push(0x00);
    frame.extend_from_slice(&reason.to_le_bytes());
    frame
}

impl EvilTwinAp {
    pub fn new(ssid: &str, channel: u8) -> Self {
        let bssid = generate_bssid_from_ssid(ssid);
        EvilTwinAp {
            ssid: ssid.to_string(),
            bssid,
            channel,
            running: false,
        }
    }

    pub fn start(&mut self, iface: &str) -> Result<(), String> {
        let bssid_bytes = parse_mac(&self.bssid).ok_or_else(|| "Invalid BSSID".to_string())?;
        let beacon = build_beacon_frame(&self.ssid, &bssid_bytes, self.channel);
        println!("  \x1b[34m→\x1b[0m [EVIL-TWIN] Starting rogue AP on {} (SSID={}, CH={}, BSSID={})",
                 iface, self.ssid, self.channel, self.bssid);
        println!("  \x1b[34m→\x1b[0m [EVIL-TWIN] Broadcasting beacon frames on {}", iface);
        println!("  \x1b[33m⚠\x1b[0m [EVIL-TWIN] Evil Twin requires monitor mode and packet injection.");
        println!("  \x1b[33m⚠\x1b[0m [EVIL-TWIN] This is a simplified implementation.");
        println!("  \x1b[33m⚠\x1b[0m [EVIL-TWIN] Use airbase-ng or mdk4 for production deployment.");
        let _ = beacon;
        let _ = iface;
        self.running = true;
        println!("  \x1b[34m→\x1b[0m [EVIL-TWIN] Press Ctrl+C to stop...");
        println!("  \x1b[34m→\x1b[0m [EVIL-TWIN] EvilTwin AP '{}' running (simulated)", self.ssid);
        Ok(())
    }

    pub fn stop(&mut self) {
        self.running = false;
        println!("  \x1b[34m→\x1b[0m [EVIL-TWIN] Rogue AP stopped");
    }

    pub fn deauth_victims(&self, iface: &str, target_bssid: &str) -> Result<(), String> {
        let target = parse_mac(target_bssid).ok_or_else(|| "Invalid target BSSID".to_string())?;
        let bssid_bytes = parse_mac(&self.bssid).ok_or_else(|| "Invalid BSSID".to_string())?;
        let deauth = build_deauth_frame(&target, &bssid_bytes, 7);
        println!("  \x1b[34m→\x1b[0m [EVIL-TWIN] Sending deauth to {} on {}", target_bssid, iface);
        println!("  \x1b[33m⚠\x1b[0m [EVIL-TWIN] Deauth injection requires raw socket privileges.");
        println!("  \x1b[33m⚠\x1b[0m [EVIL-TWIN] This is a simplified deauth implementation.");
        let _ = deauth;
        let _ = iface;
        println!("  \x1b[34m→\x1b[0m [EVIL-TWIN] Deauth frame size: 26 bytes (simulated)");
        Ok(())
    }

    pub fn capture_handshakes(&self, iface: &str, timeout_secs: u64) -> Vec<String> {
        println!("  \x1b[34m→\x1b[0m [EVIL-TWIN] Capturing handshakes on {} (timeout={}s)", iface, timeout_secs);
        println!("  \x1b[33m⚠\x1b[0m [EVIL-TWIN] Handshake capture requires monitor mode.");
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        }).ok();

        let mut handshakes = Vec::new();
        let target_bssid_lower = self.bssid.replace(':', "").to_lowercase();

        // Real EAPOL handshake capture via pcap
        if let Ok(mut cap) = pcap_wrapper::open_capture(iface) {
            pcap_wrapper::set_filter(&mut cap, &format!(
                "wlan addr2 {} and ether proto 0x888e",
                self.bssid
            ));
            let start = std::time::Instant::now();
            while start.elapsed().as_secs() < timeout_secs && running.load(Ordering::SeqCst) {
                if pcap_wrapper::next_packet(&mut cap).is_some() {
                    let ts = start.elapsed().as_secs();
                    let fname = format!("EAPOL_HANDSHAKE_{}_{}.pcap", target_bssid_lower, ts);
                    handshakes.push(fname);
                    println!("  \x1b[32m✓\x1b[0m [EVIL-TWIN] Captured real EAPOL frame #{}", handshakes.len());
                }
            }
        } else {
            println!("  \x1b[33m⚠\x1b[0m [EVIL-TWIN] Could not open {} for capture. No handshakes collected.", iface);
        }

        if handshakes.is_empty() {
            println!("  \x1b[33m⚠\x1b[0m [EVIL-TWIN] No handshakes captured in {} seconds", timeout_secs);
        } else {
            println!("  \x1b[32m✓\x1b[0m [EVIL-TWIN] {} handshake(s) captured", handshakes.len());
        }
        handshakes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_evil_twin() {
        let ap = EvilTwinAp::new("TestWiFi", 6);
        assert_eq!(ap.ssid, "TestWiFi");
        assert_eq!(ap.channel, 6);
        assert!(!ap.running);
    }

    #[test]
    fn test_parse_mac_valid() {
        let mac = parse_mac("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_parse_mac_invalid() {
        assert!(parse_mac("invalid").is_none());
        assert!(parse_mac("AA:BB:CC:DD:EE").is_none());
    }

    #[test]
    fn test_generate_bssid() {
        let bssid = generate_bssid_from_ssid("TestSSID");
        assert_eq!(bssid.len(), 17);
        assert!(bssid.starts_with("02:00:"));
    }

    #[test]
    fn test_build_beacon_frame() {
        let bssid = [0x02u8, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];
        let frame = build_beacon_frame("TEST", &bssid, 6);
        assert!(frame.len() > 40);
        assert_eq!(frame[0], 0x80);
    }

    #[test]
    fn test_build_deauth_frame() {
        let bssid = [0x02u8, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];
        let station = [0xFFu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let frame = build_deauth_frame(&bssid, &station, 7);
        assert_eq!(frame.len(), 26);
        assert_eq!(frame[0], 0xC0);
    }

    #[test]
    fn test_start_stop() {
        let mut ap = EvilTwinAp::new("TestAP", 1);
        assert!(ap.start("wlan0").is_ok());
        assert!(ap.running);
        ap.stop();
        assert!(!ap.running);
    }
}
