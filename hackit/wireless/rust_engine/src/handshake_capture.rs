use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const PCAP_MAGIC: u32 = 0xa1b2c3d4;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const PCAP_SNAPLEN: u32 = 65535;
const PCAP_LINKTYPE_IEEE80211: u32 = 105;

pub struct HandshakeCapture {
    interface: String,
    pcap_file: Option<std::fs::File>,
    filename: String,
    handshakes: Vec<Value>,
    running: Arc<AtomicBool>,
    packet_count: u64,
}

impl HandshakeCapture {
    pub fn new(interface: &str) -> Self {
        HandshakeCapture {
            interface: interface.to_string(),
            pcap_file: None,
            filename: String::new(),
            handshakes: Vec::new(),
            running: Arc::new(AtomicBool::new(false)),
            packet_count: 0,
        }
    }

    pub fn start_capture(&mut self, output: &str, timeout_secs: u64) -> Value {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(output);

        match file {
            Ok(mut f) => {
                write_pcap_header(&mut f);
                self.pcap_file = Some(f);
                self.filename = output.to_string();
                self.running.store(true, Ordering::SeqCst);
                let running = self.running.clone();
                let iface = self.interface.clone();

                let cap_thread = thread::spawn(move || {
                    let mut session = match open_pcap_session(&iface) {
                        Some(s) => s,
                        None => return Vec::new(),
                    };
                    let mut frames = Vec::new();
                    while running.load(Ordering::SeqCst) {
                        match session.next() {
                            Ok(pkt) => {
                                frames.push(pkt.data.to_vec());
                            }
                            Err(_) => break,
                        }
                    }
                    frames
                });

                thread::sleep(Duration::from_secs(timeout_secs));
                self.running.store(false, Ordering::SeqCst);

                match cap_thread.join() {
                    Ok(frames) => {
                        let mut detected = Vec::new();
                        for frame in &frames {
                            self.write_raw_packet(frame);
                            if let Some(step) = detect_eapol_step(frame) {
                                detected.push(json!({
                                    "step": step,
                                    "length": frame.len(),
                                    "timestamp": chrono_now()
                                }));
                            }
                        }
                        self.packet_count = frames.len() as u64;

                        json!({
                            "interface": self.interface,
                            "output": self.filename,
                            "packets_captured": self.packet_count,
                            "eapol_frames": detected.len(),
                            "eapol_steps": detected,
                            "status": "capturing_complete"
                        })
                    }
                    Err(e) => json!({
                        "error": format!("Capture thread panic: {:?}", e),
                        "status": "failed"
                    }),
                }
            }
            Err(e) => json!({
                "error": format!("Cannot open pcap file: {}", e),
                "status": "failed"
            }),
        }
    }

    pub fn stop_capture(&mut self) -> Value {
        self.running.store(false, Ordering::SeqCst);
        self.close_pcap();
        json!({
            "interface": self.interface,
            "packets_captured": self.packet_count,
            "handshakes_found": self.handshakes.len(),
            "status": "stopped"
        })
    }

    pub fn get_handshakes(&self) -> Value {
        json!({
            "interface": self.interface,
            "count": self.handshakes.len(),
            "handshakes": self.handshakes
        })
    }

    pub fn save_pcap(&mut self, filename: &str) -> Value {
        if self.pcap_file.is_some() {
            self.close_pcap();
        }
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(filename);
        match file {
            Ok(mut f) => {
                let _ = write_pcap_header(&mut f);
                self.pcap_file = Some(f);
                self.filename = filename.to_string();
                json!({
                    "file": filename,
                    "status": "opened"
                })
            }
            Err(e) => json!({
                "error": format!("{}", e),
                "status": "failed"
            }),
        }
    }

    pub fn extract_pmkid(data: &[u8]) -> Option<String> {
        if data.len() < 30 || data[24] != 0xAA || data[25] != 0xAA || data[30] != 0x88 || data[31] != 0x8E {
            return None;
        }
        let key_info_offset = 35;
        if data.len() < key_info_offset + 2 {
            return None;
        }
        let key_info = u16::from_le_bytes([data[key_info_offset], data[key_info_offset + 1]]);
        let is_m3 = (key_info & 0x0100) != 0;
        if !is_m3 {
            return None;
        }
        let pmkid_offset = key_info_offset + 97;
        if data.len() < pmkid_offset + 16 {
            return None;
        }
        let pmkid = &data[pmkid_offset..pmkid_offset + 16];
        Some(
            pmkid.iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(":"),
        )
    }

    fn write_raw_packet(&mut self, data: &[u8]) {
        if let Some(ref mut f) = self.pcap_file {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as u32;
            let len = data.len() as u32;
            let _ = f.write_all(&ts.to_le_bytes());
            let _ = f.write_all(&0u32.to_le_bytes());
            let _ = f.write_all(&len.to_le_bytes());
            let _ = f.write_all(&len.to_le_bytes());
            let _ = f.write_all(data);
        }
    }

    fn close_pcap(&mut self) {
        if let Some(f) = self.pcap_file.take() {
            drop(f);
        }
    }
}

fn write_pcap_header(f: &mut std::fs::File) {
    let _ = f.write_all(&PCAP_MAGIC.to_le_bytes());
    let _ = f.write_all(&PCAP_VERSION_MAJOR.to_le_bytes());
    let _ = f.write_all(&PCAP_VERSION_MINOR.to_le_bytes());
    let _ = f.write_all(&0i32.to_le_bytes());
    let _ = f.write_all(&0u32.to_le_bytes());
    let _ = f.write_all(&PCAP_SNAPLEN.to_le_bytes());
    let _ = f.write_all(&PCAP_LINKTYPE_IEEE80211.to_le_bytes());
}

fn open_pcap_session(iface: &str) -> Option<pcap::Capture<pcap::Active>> {
    #[cfg(feature = "pcap")]
    {
        match pcap::Capture::from_device(iface) {
            Ok(dev) => match dev.promisc(true).snaplen(65535).timeout(100).open() {
                Ok(cap) => Some(cap),
                Err(e) => {
                    eprintln!("[-] pcap open failed: {}", e);
                    None
                }
            },
            Err(e) => {
                eprintln!("[-] pcap device error: {}", e);
                None
            }
        }
    }
    #[cfg(not(feature = "pcap"))]
    {
        let _ = iface;
        None
    }
}

fn detect_eapol_step(data: &[u8]) -> Option<u8> {
    if data.len() < 32 {
        return None;
    }
    if data.len() > 24 && data[24] == 0xAA && data[25] == 0xAA && data[30] == 0x88 && data[31] == 0x8E {
        let eapol_len = data.len();
        if eapol_len > 38 {
            let desc_type = data[37];
            match desc_type {
                1 => Some(1),
                2 => Some(2),
                3 => Some(3),
                4 => Some(4),
                _ => None,
            }
        } else {
            Some(0)
        }
    } else {
        None
    }
}

fn chrono_now() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}", d)
}

// mod handshake_capture;
