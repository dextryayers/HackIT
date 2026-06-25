use std::fs::{File, OpenOptions};
use std::io::Write;

const PCAP_MAGIC: u32 = 0xa1b2c3d4;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const PCAP_SNAPLEN: u32 = 65535;
const PCAP_LINKTYPE_IEEE80211: u32 = 105;

#[derive(Debug, Clone)]
pub struct RsnInfo {
    pub version: u16,
    pub group_cipher: u32,
    pub pairwise_ciphers: Vec<u32>,
    pub akms: Vec<u32>,
    pub capabilities: u16,
    pub pmkid: Option<[u8; 16]>,
}

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

    pub fn open_pcap(&mut self, filename: &str) -> bool {
        match OpenOptions::new().write(true).create(true).truncate(true).open(filename) {
            Ok(mut f) => {
                let _ = f.write_all(&PCAP_MAGIC.to_le_bytes());
                let _ = f.write_all(&PCAP_VERSION_MAJOR.to_le_bytes());
                let _ = f.write_all(&PCAP_VERSION_MINOR.to_le_bytes());
                let _ = f.write_all(&0i32.to_le_bytes());
                let _ = f.write_all(&0u32.to_le_bytes());
                let _ = f.write_all(&PCAP_SNAPLEN.to_le_bytes());
                let _ = f.write_all(&PCAP_LINKTYPE_IEEE80211.to_le_bytes());
                self.file = Some(f);
                self.filename = filename.to_string();
                self.packet_count = 0;
                true
            }
            Err(e) => {
                eprintln!("[-] Failed to open PCAP file '{}': {}", filename, e);
                false
            }
        }
    }

    pub fn write_packet(&mut self, data: &[u8]) {
        if let Some(ref mut f) = self.file {
            let ts_sec = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as u32;
            let ts_usec = 0u32;
            let orig_len = data.len() as u32;
            let incl_len = orig_len.min(PCAP_SNAPLEN);
            let _ = f.write_all(&ts_sec.to_le_bytes());
            let _ = f.write_all(&ts_usec.to_le_bytes());
            let _ = f.write_all(&incl_len.to_le_bytes());
            let _ = f.write_all(&orig_len.to_le_bytes());
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

fn ie_iter(data: &[u8], start: usize) -> impl Iterator<Item = (u8, u8, usize)> + '_ {
    let mut offset = start;
    std::iter::from_fn(move || {
        if offset + 2 > data.len() {
            return None;
        }
        let id = data[offset];
        let len = data[offset + 1] as usize;
        if offset + 2 + len > data.len() {
            return None;
        }
        let val_start = offset;
        offset += 2 + len;
        Some((id, len as u8, val_start))
    })
}

pub fn extract_ssid_from_beacon(data: &[u8]) -> String {
    if data.len() < 36 {
        return String::new();
    }
    let fc = data[0];
    let frame_type = (fc >> 2) & 0x03;
    let frame_subtype = (fc >> 4) & 0x0F;
    if frame_type != 0 || frame_subtype != 8 {
        return String::new();
    }
    let fixed_params_end = 36;
    for (id, len, start) in ie_iter(data, fixed_params_end) {
        if id == 0 && len > 0 {
            let ssid_bytes = &data[start + 2..start + 2 + len as usize];
            if let Ok(s) = std::str::from_utf8(ssid_bytes) {
                let trimmed = s.trim_matches('\0');
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
        if id == 0 {
            break;
        }
    }
    "<hidden>".to_string()
}

pub fn extract_rates(data: &[u8]) -> Vec<u8> {
    if data.len() < 36 {
        return Vec::new();
    }
    let fc = data[0];
    let frame_type = (fc >> 2) & 0x03;
    let frame_subtype = (fc >> 4) & 0x0F;
    if frame_type != 0 || frame_subtype != 8 {
        return Vec::new();
    }
    let fixed_params_end = 36;
    let mut rates = Vec::new();
    for (id, len, start) in ie_iter(data, fixed_params_end) {
        if id == 1 && len > 0 {
            rates.extend_from_slice(&data[start + 2..start + 2 + len as usize]);
            break;
        }
    }
    rates
}

pub fn extract_channel(data: &[u8]) -> u8 {
    if data.len() < 36 {
        return 0;
    }
    let fc = data[0];
    let frame_type = (fc >> 2) & 0x03;
    let frame_subtype = (fc >> 4) & 0x0F;
    if frame_type != 0 || frame_subtype != 8 {
        return 0;
    }
    let fixed_params_end = 36;
    for (id, len, start) in ie_iter(data, fixed_params_end) {
        if id == 3 && len >= 1 {
            return data[start + 2];
        }
    }
    0
}

fn parse_cipher_suite(oui_type: &[u8]) -> u32 {
    if oui_type.len() < 4 {
        return 0;
    }
    ((oui_type[0] as u32) << 24) | ((oui_type[1] as u32) << 16) |
    ((oui_type[2] as u32) << 8) | (oui_type[3] as u32)
}

pub fn extract_rsn(data: &[u8]) -> Option<RsnInfo> {
    if data.len() < 36 {
        return None;
    }
    let fixed_params_end = 36;
    for (id, _len, start) in ie_iter(data, fixed_params_end) {
        if id != 48 && id != 0xDD {
            continue;
        }
        if id == 0xDD {
            if start + 6 > data.len() {
                continue;
            }
            let oui = &data[start + 2..start + 6];
            if oui.len() < 4 || oui[0] != 0x00 || oui[1] != 0x50 || oui[2] != 0xF2 || oui[3] != 0x01 {
                continue;
            }
        }
        let body_start = start + 2;
        let body = &data[body_start..];
        if body.len() < 8 {
            continue;
        }
        let version = u16::from_le_bytes([body[0], body[1]]);
        let group_suite = &body[2..6];
        if group_suite.len() < 4 {
            continue;
        }
        let group_cipher = parse_cipher_suite(group_suite);
        let pairwise_count = u16::from_le_bytes([body[6], body[7]]) as usize;
        let mut pos = 8;
        let mut pairwise_ciphers = Vec::new();
        for _ in 0..pairwise_count {
            if pos + 4 > body.len() {
                break;
            }
            pairwise_ciphers.push(parse_cipher_suite(&body[pos..pos + 4]));
            pos += 4;
        }
        if pos + 2 > body.len() {
            return Some(RsnInfo {
                version,
                group_cipher,
                pairwise_ciphers,
                akms: Vec::new(),
                capabilities: 0,
                pmkid: None,
            });
        }
        let akm_count = u16::from_le_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;
        let mut akms = Vec::new();
        for _ in 0..akm_count {
            if pos + 4 > body.len() {
                break;
            }
            akms.push(parse_cipher_suite(&body[pos..pos + 4]));
            pos += 4;
        }
        if pos + 2 > body.len() {
            return Some(RsnInfo {
                version,
                group_cipher,
                pairwise_ciphers,
                akms,
                capabilities: 0,
                pmkid: None,
            });
        }
        let capabilities = u16::from_le_bytes([body[pos], body[pos + 1]]);
        pos += 2;
        let mut pmkid = None;
        if (capabilities & 0x0020) != 0 && pos + 2 <= body.len() {
            let pmkid_count = u16::from_le_bytes([body[pos], body[pos + 1]]) as usize;
            pos += 2;
            if pmkid_count > 0 && pos + 16 <= body.len() {
                let mut pmk = [0u8; 16];
                pmk.copy_from_slice(&body[pos..pos + 16]);
                pmkid = Some(pmk);
            }
        }
        return Some(RsnInfo {
            version,
            group_cipher,
            pairwise_ciphers,
            akms,
            capabilities,
            pmkid,
        });
    }
    None
}

pub fn detect_eapol_step(frame: &[u8]) -> Option<u8> {
    if frame.len() < 36 { return None; }
    let snap_start = 24;
    if snap_start + 8 > frame.len() { return None; }
    if frame[snap_start] == 0xAA &&
       frame[snap_start+1] == 0xAA &&
       frame[snap_start+2] == 0x03 &&
       frame[snap_start+6] == 0x88 &&
       frame[snap_start+7] == 0x8E
    {
        let eapol_start = snap_start + 8;
        if eapol_start + 4 > frame.len() { return None; }
        let eapol_type = frame[eapol_start + 1];
        if eapol_type != 0x03 { return None; }
        let key_info_high  = frame.get(eapol_start + 5).copied().unwrap_or(0);
        let key_info_low   = frame.get(eapol_start + 6).copied().unwrap_or(0);
        let key_info: u16 = ((key_info_high as u16) << 8) | (key_info_low as u16);
        let ack = (key_info >> 7) & 1;
        let mic = (key_info >> 8) & 1;
        let install = (key_info >> 6) & 1;
        if ack == 1 && mic == 0 { return Some(1); }
        if ack == 0 && mic == 1 && install == 0 { return Some(2); }
        if ack == 1 && mic == 1 && install == 1 { return Some(3); }
        if ack == 0 && mic == 1 { return Some(4); }
    }
    None
}

pub fn extract_pmkid(frame: &[u8]) -> Option<String> {
    let snap_start = 24;
    let eapol_start = snap_start + 8;
    if eapol_start + 100 > frame.len() { return None; }
    let key_data_len = ((frame[eapol_start + 97] as usize) << 8) | (frame[eapol_start + 98] as usize);
    if key_data_len < 22 { return None; }
    let key_data_start = eapol_start + 99;
    if key_data_start + key_data_len > frame.len() { return None; }
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

pub fn build_deauth_frame(target_bssid: &str, station_mac: &str, reason_code: u16) -> Option<Vec<u8>> {
    let bssid_bytes = parse_mac(target_bssid)?;
    let station_bytes = parse_mac(station_mac)?;
    let mut frame = Vec::with_capacity(26);
    frame.push(0xC0);
    frame.push(0x00);
    frame.push(0x3A);
    frame.push(0x01);
    frame.extend_from_slice(&station_bytes);
    frame.extend_from_slice(&bssid_bytes);
    frame.extend_from_slice(&bssid_bytes);
    frame.push(0x00);
    frame.push(0x00);
    frame.push((reason_code & 0xFF) as u8);
    frame.push(((reason_code >> 8) & 0xFF) as u8);
    Some(frame)
}

pub fn build_beacon_frame(ssid: &str, bssid_mac: &str, channel: u8) -> Vec<u8> {
    let bssid_bytes = parse_mac(bssid_mac).unwrap_or([0u8; 6]);
    let broadcast = [0xFFu8; 6];
    let mut frame = Vec::new();
    frame.push(0x80); frame.push(0x00);
    frame.push(0x00); frame.push(0x00);
    frame.extend_from_slice(&broadcast);
    frame.extend_from_slice(&bssid_bytes);
    frame.extend_from_slice(&bssid_bytes);
    frame.push(0x00); frame.push(0x00);
    frame.extend_from_slice(&[0u8; 8]);
    frame.push(0x64); frame.push(0x00);
    frame.push(0x11); frame.push(0x04);
    let ssid_bytes = ssid.as_bytes();
    frame.push(0x00); frame.push(ssid_bytes.len() as u8);
    frame.extend_from_slice(ssid_bytes);
    frame.push(0x01); frame.push(0x08);
    frame.extend_from_slice(&[0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C]);
    frame.push(0x03); frame.push(0x01); frame.push(channel);
    frame.push(0x30); frame.push(0x14);
    frame.push(0x01); frame.push(0x00);
    frame.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]);
    frame.push(0x01); frame.push(0x00);
    frame.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]);
    frame.push(0x01); frame.push(0x00);
    frame.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x02]);
    frame.push(0x00); frame.push(0x00);
    frame
}

pub fn build_auth_frame(bssid: &str, station: &str, algo: u16, seq: u16, status: u16) -> Option<Vec<u8>> {
    let bssid_bytes = parse_mac(bssid)?;
    let station_bytes = parse_mac(station)?;
    let mut frame = Vec::with_capacity(30);
    frame.push(0xB0);
    frame.push(0x00);
    frame.push(0x3A);
    frame.push(0x01);
    frame.extend_from_slice(&bssid_bytes);
    frame.extend_from_slice(&station_bytes);
    frame.extend_from_slice(&bssid_bytes);
    frame.push(0x00);
    frame.push(0x00);
    frame.push((algo & 0xFF) as u8);
    frame.push(((algo >> 8) & 0xFF) as u8);
    frame.push((seq & 0xFF) as u8);
    frame.push(((seq >> 8) & 0xFF) as u8);
    frame.push((status & 0xFF) as u8);
    frame.push(((status >> 8) & 0xFF) as u8);
    Some(frame)
}

pub fn build_assoc_req(bssid: &str, station: &str, ssid: &str) -> Option<Vec<u8>> {
    let bssid_bytes = parse_mac(bssid)?;
    let station_bytes = parse_mac(station)?;
    let ssid_bytes = ssid.as_bytes();
    let mut frame = Vec::with_capacity(38 + ssid_bytes.len());
    frame.push(0x00);
    frame.push(0x00);
    frame.push(0x3A);
    frame.push(0x01);
    frame.extend_from_slice(&bssid_bytes);
    frame.extend_from_slice(&station_bytes);
    frame.extend_from_slice(&bssid_bytes);
    frame.push(0x00);
    frame.push(0x00);
    frame.push(0x11);
    frame.push(0x04);
    frame.push(0x0A);
    frame.push(0x00);
    frame.push(0x00);
    frame.push(ssid_bytes.len() as u8);
    frame.extend_from_slice(ssid_bytes);
    Some(frame)
}

pub fn build_arp_packet(src_mac: &[u8; 6], dst_mac: &[u8; 6], src_ip: &[u8; 4], dst_ip: &[u8; 4], op: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(28);
    pkt.push(0x00); pkt.push(0x01);
    pkt.push(0x08); pkt.push(0x00);
    pkt.push(0x06);
    pkt.push(0x04);
    pkt.push(((op >> 8) & 0xFF) as u8);
    pkt.push((op & 0xFF) as u8);
    pkt.extend_from_slice(src_mac);
    pkt.extend_from_slice(src_ip);
    pkt.extend_from_slice(dst_mac);
    pkt.extend_from_slice(dst_ip);
    pkt
}

pub fn build_data_frame(bssid: &str, station: &str, payload: &[u8]) -> Option<Vec<u8>> {
    let bssid_bytes = parse_mac(bssid)?;
    let station_bytes = parse_mac(station)?;
    let mut frame = Vec::with_capacity(28 + payload.len());
    frame.push(0x08);
    frame.push(0x42);
    frame.push(0x3A);
    frame.push(0x01);
    frame.extend_from_slice(&bssid_bytes);
    frame.extend_from_slice(&station_bytes);
    frame.extend_from_slice(&bssid_bytes);
    frame.push(0x00);
    frame.push(0x00);
    frame.push(0x00);
    frame.push(0x00);
    let snap: [u8; 8] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00];
    frame.extend_from_slice(&snap);
    frame.extend_from_slice(payload);
    Some(frame)
}

pub fn verify_handshake_pcap(path: &str) -> Result<String, String> {
    let data = std::fs::read(path).map_err(|e| format!("Cannot read {}: {}", path, e))?;
    if data.len() < 24 { return Err("Not a valid PCAP file (too short)".into()); }
    let mut offset = 24usize;
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

pub fn convert_pcap_to_hc22000(input: &str, output: &str) -> Result<String, String> {
    let data = std::fs::read(input).map_err(|e| format!("Cannot read {}: {}", e, input))?;
    if data.len() < 24 { return Err("Not a valid PCAP file".into()); }
    let mut offset = 24usize;
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
            let eapol_start = 32;
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
    let ap_mac = if m1.len() > 8 { hex_str(&m1[6..8]) } else { "000000000000".into() };
    let sta_mac = if m2.len() > 8 { hex_str(&m2[6..8]) } else { "000000000000".into() };
    let line = format!(
        "WPA*01*{:016x}*{:016x}*{:016x}*{}*{}*{}***",
        0u64,
        u64::from_be_bytes([m1[29], m1[30], m1[31], m1[32], m1[33], m1[34], m1[35], m1[36]]),
        0u64,
        ap_mac, sta_mac,
        ""
    );
    let mut out = std::fs::File::create(output)
        .map_err(|e| format!("Cannot write {}: {}", output, e))?;
    out.write_all(line.as_bytes()).map_err(|e| format!("Write error: {}", e))?;
    out.write_all(b"\n").ok();
    Ok(format!("Converted -> {} (HC22000)", output))
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn parse_mac(mac: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = mac.split([':', '-']).collect();
    if parts.len() != 6 { return None; }
    let mut bytes = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        bytes[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(bytes)
}
