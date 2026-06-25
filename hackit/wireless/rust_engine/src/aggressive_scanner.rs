use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;

const CHANNELS_2GHZ: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
const CHANNELS_5GHZ: &[u8] = &[
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165,
];
const CHANNELS_SUBGHZ: &[u8] = &[100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144];

pub struct AggressiveScanner {
    interface: String,
    results: Arc<Mutex<Vec<Value>>>,
    seen_bssids: Arc<Mutex<HashMap<String, Vec<Value>>>>,
}

impl AggressiveScanner {
    pub fn new(interface: &str) -> Self {
        AggressiveScanner {
            interface: interface.to_string(),
            results: Arc::new(Mutex::new(Vec::new())),
            seen_bssids: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn scan_all(&self) -> Value {
        let mut all_channels = Vec::new();
        all_channels.extend_from_slice(CHANNELS_2GHZ);
        all_channels.extend_from_slice(CHANNELS_5GHZ);
        all_channels.extend_from_slice(CHANNELS_SUBGHZ);
        self.scan_channel_range(&all_channels)
    }

    pub fn scan_channel_range(&self, channels: &[u8]) -> Value {
        let start = std::time::Instant::now();
        let mut handles = Vec::new();

        for chunk in channels.chunks(4) {
            let iface = self.interface.clone();
            let results = self.results.clone();
            let seen = self.seen_bssids.clone();
            let chans = chunk.to_vec();

            handles.push(thread::spawn(move || {
                for &ch in &chans {
                    let chan_result = Self::scan_single_channel(&iface, ch);
                    if let Some(ap) = chan_result {
                        let mut seen_lock = seen.lock().unwrap();
                        let entry = seen_lock.entry(ap["bssid"].as_str().unwrap_or("").to_string()).or_insert_with(Vec::new);
                        entry.push(ap.clone());
                        let mut res_lock = results.lock().unwrap();
                        res_lock.push(ap);
                    }
                }
            }));
        }

        for h in handles {
            let _ = h.join();
        }

        let mut all = self.results.lock().unwrap().clone();
        all.sort_by(|a, b| b["signal"].as_i64().unwrap_or(-100).cmp(&a["signal"].as_i64().unwrap_or(-100)));

        let elapsed = start.elapsed().as_secs_f64();
        json!({
            "interface": self.interface,
            "channels_scanned": channels.len(),
            "aps_found": all.len(),
            "elapsed_secs": elapsed,
            "access_points": all
        })
    }

    fn scan_single_channel(iface: &str, channel: u8) -> Option<Value> {
        let output = std::process::Command::new("iw")
            .args(["dev", iface, "set", "channel", &channel.to_string()])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        thread::sleep(std::time::Duration::from_millis(50));

        let scan_out = std::process::Command::new("iw")
            .args(["dev", iface, "scan", "-f"])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&scan_out.stdout);
        let mut current_bssid = String::new();
        let mut current_signal: i64 = -100;
        let mut current_ssid = String::new();
        let mut found_bssid = false;

        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("BSS ") {
                if found_bssid && !current_bssid.is_empty() {
                    let result = json!({
                        "bssid": current_bssid,
                        "ssid": current_ssid,
                        "channel": channel,
                        "signal": current_signal,
                        "encryption": "unknown",
                        "vendor": detect_vendor(&current_bssid)
                    });
                    current_bssid.clear();
                    current_ssid.clear();
                    return Some(result);
                }
                let parts: Vec<&str> = trimmed.splitn(2, '(').collect();
                let mac_part = parts[0].trim().trim_start_matches("BSS ");
                current_bssid = mac_part.trim().to_uppercase();
                found_bssid = true;
            } else if trimmed.starts_with("SSID:") {
                current_ssid = trimmed.trim_start_matches("SSID:").trim().to_string();
            } else if trimmed.starts_with("signal:") {
                let sig_str = trimmed.trim_start_matches("signal:").trim();
                let sig_val = sig_str.split_whitespace().next().unwrap_or("-100");
                current_signal = sig_val.parse::<f64>().unwrap_or(-100.0) as i64;
            }
        }

        if found_bssid && !current_bssid.is_empty() {
            Some(json!({
                "bssid": current_bssid,
                "ssid": current_ssid,
                "channel": channel,
                "signal": current_signal,
                "encryption": "unknown",
                "vendor": detect_vendor(&current_bssid)
            }))
        } else {
            None
        }
    }

    pub fn detect_hidden(&self, channels: &[u8]) -> Value {
        let mut hidden_aps = Vec::new();
        let mut sent_probes = 0u64;

        for &ch in channels {
            let _ = std::process::Command::new("iw")
                .args(["dev", &self.interface, "set", "channel", &ch.to_string()])
                .output();

            for _ in 0..5 {
                let probe = build_probe_request_frame("", ch);
                let _ = std::process::Command::new("iw")
                    .args(["dev", &self.interface, "inject"])
                    .output();
                sent_probes += 1;
                let _ = std::process::Command::new("iw")
                    .args(["dev", &self.interface, "inject", "-f", "-"])
                    .arg(std::str::from_utf8(&probe).unwrap_or(""))
                    .output();
            }

            thread::sleep(std::time::Duration::from_millis(30));

            let scan_out = std::process::Command::new("iw")
                .args(["dev", &self.interface, "scan", "-f"])
                .output()
                .ok();

            if let Some(out) = scan_out {
                let stdout = String::from_utf8_lossy(&out.stdout);
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("BSS ") && !trimmed.contains("(on") {
                        let parts: Vec<&str> = trimmed.splitn(2, '(').collect();
                        let mac = parts[0].trim().trim_start_matches("BSS ").trim().to_uppercase();
                        hidden_aps.push(json!({
                            "bssid": mac,
                            "channel": ch,
                            "hidden": true,
                            "detected_by": "probe_flood"
                        }));
                    }
                }
            }
        }

        json!({
            "interface": self.interface,
            "hidden_aps_found": hidden_aps.len(),
            "probe_requests_sent": sent_probes,
            "access_points": hidden_aps
        })
    }

    pub fn average_signal(&self, bssid: &str, samples: usize) -> Value {
        let mut readings = Vec::new();
        for _ in 0..samples {
            let out = std::process::Command::new("iw")
                .args(["dev", &self.interface, "scan", "-f"])
                .output()
                .ok();
            if let Some(out) = out {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let mut in_target = false;
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("BSS ") && trimmed.contains(bssid) {
                        in_target = true;
                    } else if trimmed.starts_with("BSS ") {
                        in_target = false;
                    }
                    if in_target && trimmed.starts_with("signal:") {
                        let sig_str = trimmed.trim_start_matches("signal:").trim();
                        if let Some(val) = sig_str.split_whitespace().next() {
                            if let Ok(s) = val.parse::<f64>() {
                                readings.push(s);
                            }
                        }
                    }
                }
            }
            thread::sleep(std::time::Duration::from_millis(100));
        }

        let avg = if readings.is_empty() {
            0.0
        } else {
            readings.iter().sum::<f64>() / readings.len() as f64
        };

        json!({
            "bssid": bssid,
            "samples": readings.len(),
            "average_signal_dbm": avg,
            "readings": readings
        })
    }
}

fn detect_vendor(bssid: &str) -> String {
    let clean = bssid.replace(':', "").to_uppercase();
    if clean.len() < 6 {
        return "Unknown".to_string();
    }
    match &clean[..6] {
        "001122" | "00226B" => "Cisco",
        "3C5AB4" => "Google",
        "44E9DD" | "AC84C6" | "B04E26" | "C025E9" | "E894F6" | "F4F26D" => "TP-Link",
        "5CA6E6" | "788A20" => "Ubiquiti",
        "60A44C" => "ASUSTek",
        "D8F15B" => "Netgear",
        "00260B" => "Amazon",
        _ => "Unknown",
    }
    .to_string()
}

pub fn aggressive_scan(iface: &str) -> Vec<Value> {
    let scanner = AggressiveScanner::new(iface);
    let results = scanner.scan_all();
    results["access_points"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

pub fn client_hunt(iface: &str, bssid: &str) -> Vec<String> {
    let scanner = AggressiveScanner::new(iface);
    let _bssid = if bssid.is_empty() { "FF:FF:FF:FF:FF:FF" } else { bssid };
    let _ = scanner.detect_hidden(CHANNELS_2GHZ);
    Vec::new()
}

pub fn probe_request_flood(iface: &str, ssid: &str, count: u32) -> Result<(), String> {
    let _ = ssid;
    let _ = count;
    let _ = std::process::Command::new("iw")
        .args(["dev", iface, "scan", "-f"])
        .output()
        .map_err(|e| format!("iw scan failed: {}", e))?;
    Ok(())
}

fn build_probe_request_frame(ssid: &str, _channel: u8) -> Vec<u8> {
    let mut frame = Vec::with_capacity(24 + 2 + ssid.len());
    frame.push(0x40);
    frame.push(0x00);
    frame.extend_from_slice(&[0xFF; 6]);
    frame.extend_from_slice(&[0x00; 6]);
    frame.extend_from_slice(&[0xFF; 6]);
    frame.extend_from_slice(&[0x00; 2]);
    frame.push(0x00);
    frame.push(ssid.len() as u8);
    frame.extend_from_slice(ssid.as_bytes());
    frame
}

// mod aggressive_scanner;
