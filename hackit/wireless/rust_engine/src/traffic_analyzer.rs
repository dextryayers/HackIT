
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub struct APRecord {
    pub ssid: String,
    pub bssid: String,
    pub channel: u8,
    pub rssi: i32,
    pub crypto: String,
    pub first_seen: u64,
    pub last_seen: u64,
}

pub struct TrafficAnalyzer {
    pub discovered_aps: Arc<Mutex<HashMap<String, APRecord>>>,
}

impl TrafficAnalyzer {
    pub fn new() -> Self {
        TrafficAnalyzer {
            discovered_aps: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn process_raw_frame(&self, frame: &[u8]) {
        // High-speed native parsing logic for 802.11 frames
        if frame.len() < 24 {
            return; // Too short to be a valid 802.11 MAC header
        }

        // Extremely simplified parsing logic. We rely on C++ FFI for deeper extraction,
        // but Rust handles the fast-path routing.
        let frame_ctrl = frame[0];
        let frame_type = (frame_ctrl >> 2) & 0x03;
        let frame_subtype = (frame_ctrl >> 4) & 0x0F;

        // Management Frame (0x00) -> Beacon (0x08) or Probe Response (0x05)
        if frame_type == 0 && (frame_subtype == 8 || frame_subtype == 5) {
            let bssid_bytes = &frame[16..22];
            let bssid = format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                bssid_bytes[0],
                bssid_bytes[1],
                bssid_bytes[2],
                bssid_bytes[3],
                bssid_bytes[4],
                bssid_bytes[5]
            );

            // FFI Call down to C++ here to extract SSID cleanly if we need precision
            // For now, register the AP sighting
            let mut aps = match self.discovered_aps.lock() {
                Ok(guard) => guard,
                Err(_) => return,
            };

            if !aps.contains_key(&bssid) {
                aps.insert(
                    bssid.clone(),
                    APRecord {
                        ssid: String::new(),
                        bssid: bssid.clone(),
                        channel: 0,
                        rssi: 0,
                        crypto: "Unknown".to_string(),
                        first_seen: 0,
                        last_seen: 0,
                    },
                );

                // Emitting real-time log event to console
                println!("[RUST-RECON] New Target Identified: BSSID={}", bssid);
            }
        }
    }

    pub fn get_ap_list(&self) -> Vec<APRecord> {
        let guard = self.discovered_aps.lock().unwrap();
        guard.values().cloned().collect()
    }
}
