use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

static OUI_DB: OnceLock<HashMap<String, String>> = OnceLock::new();

fn load_oui_db() -> HashMap<String, String> {
    let paths = [
        "/usr/share/ieee-data/oui.txt",
        "/var/lib/ieee-data/oui.txt",
        "/usr/local/share/ieee-data/oui.txt",
    ];
    for path in &paths {
        if let Ok(data) = std::fs::read_to_string(path) {
            let mut db = HashMap::new();
            for line in data.lines() {
                if line.len() < 12 { continue; }
                // Format: "00-00-00   (hex)          VENDOR NAME"
                // or      "000000     (base 16)      VENDOR NAME"
                let hex_prefix = &line[..8];
                if hex_prefix.len() == 8 && hex_prefix.as_bytes()[2] == b'-' && hex_prefix.as_bytes()[5] == b'-' {
                    let oui = format!("{}-{}-{}", &hex_prefix[0..2], &hex_prefix[3..5], &hex_prefix[6..8]);
                    let colon_oui = oui.replace('-', ":");
                    let name = line[18..].trim().to_string();
                    if !name.is_empty() {
                        db.entry(colon_oui.to_uppercase()).or_insert_with(|| name.clone());
                    }
                    // Also add without colon for convenience
                    db.entry(oui.to_uppercase()).or_insert_with(|| name.clone());
                }
            }
            if !db.is_empty() {
                return db;
            }
        }
    }
    HashMap::new()
}

fn oui_lookup(mac: &str) -> String {
    let db = OUI_DB.get_or_init(load_oui_db);
    if db.is_empty() {
        return "Unknown".to_string();
    }
    let upper = mac.to_uppercase();
    // First try full 8-char prefix (XX:XX:XX)
    if upper.len() >= 8 {
        if let Some(v) = db.get(&upper[..8]) {
            return v.clone();
        }
    }
    // Then try 6-char prefix (XXXXXX) without colons
    if upper.len() >= 6 {
        let nocolon: String = upper.chars().filter(|c| *c != ':').take(6).collect();
        if nocolon.len() == 6 {
            if let Some(v) = db.get(&nocolon) {
                return v.clone();
            }
        }
    }
    "Unknown".to_string()
}

#[derive(Clone, Debug)]
pub struct ApEntry {
    pub bssid: String,
    pub ssid: String,
    pub channel: u8,
    pub signal: i16,
    pub encryption: String,
    pub wps: bool,
    pub vendor: String,
    pub beacons: u64,
    pub first_seen: Instant,
    pub last_seen: Instant,
}

#[derive(Clone, Debug)]
pub struct StationEntry {
    pub mac: String,
    pub bssid: String,
    pub signal: i16,
    pub packets: u64,
    pub probes: Vec<String>,
    pub first_seen: Instant,
    pub last_seen: Instant,
}

pub struct AirodumpCapture {
    pub aps: HashMap<String, ApEntry>,
    pub stations: HashMap<String, StationEntry>,
    pub power_source: bool,
}

impl AirodumpCapture {
    pub fn new() -> Self {
        AirodumpCapture {
            aps: HashMap::new(),
            stations: HashMap::new(),
            power_source: false,
        }
    }

    pub fn process_frame(&mut self, data: &[u8]) {
        if data.len() < 24 {
            return;
        }

        // Parse radiotap header
        let radio_len = if data.len() > 3 && (data[2] == 0x00) {
            // Radiotap: length at bytes 2-3 little-endian
            let rlen = data[2] as usize | ((data[3] as usize) << 8);
            if rlen > 0 && rlen < data.len() { rlen } else { 0 }
        } else {
            0
        };
        let hdr = radio_len; // 802.11 header starts after radiotap

        if hdr + 24 > data.len() {
            return;
        }

        let fc = data[hdr];
        let frame_type = (fc >> 2) & 0x03;
        let frame_subtype = (fc >> 4) & 0x0F;

        // Signal strength from radiotap
        let signal = self.extract_signal(data, hdr);

        let sa = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            data[hdr+10], data[hdr+11], data[hdr+12], data[hdr+13], data[hdr+14], data[hdr+15]);
        let ta = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            data[hdr+16], data[hdr+17], data[hdr+18], data[hdr+19], data[hdr+20], data[hdr+21]);
        let da = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            data[hdr+22], data[hdr+23], data[hdr+24], data[hdr+25], data[hdr+26], data[hdr+27]);

        let signal = self.extract_signal(data, hdr);
        let bssid = if frame_type == 0 { sa.clone() } else { ta.clone() };

        match frame_type {
            0 => match frame_subtype {
                8 | 9 => {
                    let (ssid, channel, encryption, wps) = self.parse_beacon(data, hdr);
                    let vendor = oui_lookup(&bssid);
                    let entry = self.aps.entry(bssid.clone()).or_insert(ApEntry {
                        bssid: bssid.clone(),
                        ssid: ssid.clone(),
                        channel,
                        signal,
                        encryption: encryption.clone(),
                        wps,
                        vendor: vendor.to_string(),
                        beacons: 0,
                        first_seen: Instant::now(),
                        last_seen: Instant::now(),
                    });
                    entry.beacons += 1;
                    entry.last_seen = Instant::now();
                    entry.signal = signal;
                    if !ssid.is_empty() && entry.ssid == "<hidden>" {
                        entry.ssid = ssid;
                    }
                    if encryption != "" && entry.encryption == "" {
                        entry.encryption = encryption;
                    }
                    if wps && !entry.wps {
                        entry.wps = wps;
                    }
                }
                4 => {
                    let src = sa.clone();
                    let probes = self.extract_probes(data, hdr);
                    let entry = self.stations.entry(src.clone()).or_insert(StationEntry {
                        mac: src.clone(),
                        bssid: "".to_string(),
                        signal,
                        packets: 0,
                        probes: Vec::new(),
                        first_seen: Instant::now(),
                        last_seen: Instant::now(),
                    });
                    entry.packets += 1;
                    entry.last_seen = Instant::now();
                    entry.signal = signal;
                    for p in &probes {
                        if !entry.probes.contains(p) {
                            entry.probes.push(p.clone());
                        }
                    }
                }
                _ => {}
            },
            1 => {
                // Control frame
                if frame_subtype == 10 || frame_subtype == 11 || frame_subtype == 12 {
                    let sta = sa.clone();
                    let entry = self.stations.entry(sta.clone()).or_insert(StationEntry {
                        mac: sta.clone(),
                        bssid: "".to_string(),
                        signal,
                        packets: 0,
                        probes: Vec::new(),
                        first_seen: Instant::now(),
                        last_seen: Instant::now(),
                    });
                    entry.packets += 1;
                    entry.last_seen = Instant::now();
                    entry.signal = signal;
                }
            }
            2 => {
                let src = if da == bssid { sa.clone() } else { ta.clone() };
                let bssid_str = if frame_subtype == 8 { sa.clone() } else { bssid.clone() };
                let entry = self.stations.entry(src.clone()).or_insert(StationEntry {
                    mac: src.clone(),
                    bssid: bssid_str.clone(),
                    signal,
                    packets: 0,
                    probes: Vec::new(),
                    first_seen: Instant::now(),
                    last_seen: Instant::now(),
                });
                entry.packets += 1;
                entry.last_seen = Instant::now();
                entry.signal = signal;
                if entry.bssid.is_empty() || entry.bssid == "00:00:00:00:00:00" {
                    entry.bssid = bssid_str;
                }
            }
            _ => {}
        }
    }

    fn extract_signal(&self, data: &[u8], hdr: usize) -> i16 {
        if hdr > 8 && data.len() > 7 {
            // Radiotap v0 at data[0..hdr]
            // it_version at 0, it_len at 2-3, it_present at 4-7 (first word)
            let it_present = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
            let mut field_off = hdr; // start after radiotap header
            // Walk bits 0=TSFT, 1=Flags, 2=Rate, 3=Channel, 4=FHSS, 5=AntennaSignal, ...
            let fields: &[(u32, usize)] = &[
                (1 << 0, 8), (1 << 1, 1), (1 << 2, 1), (1 << 3, 4),
                (1 << 4, 2), (1 << 5, 1),
            ];
            for (mask, size) in fields {
                if it_present & mask != 0 {
                    if field_off + size <= data.len() {
                        if *mask == 1 << 5 {
                            let sig = data[field_off] as i16;
                            return if sig > 0 && sig < 128 { -sig } else if sig > -128 && sig <= 0 { sig } else { -50 };
                        }
                        field_off += size;
                    } else {
                        break;
                    }
                }
            }
        }
        -50
    }

    fn parse_beacon(&self, data: &[u8], hdr: usize) -> (String, u8, String, bool) {
        let mut ssid = String::new();
        let mut channel = 0u8;
        let mut encryption = String::new();
        let mut wps = false;

        let mut offset = hdr + 36usize;
        loop {
            if offset + 2 > data.len() { break; }
            let id = data[offset];
            let len = data[offset + 1] as usize;
            if offset + 2 + len > data.len() { break; }

            match id {
                0 if len > 0 => {
                    if let Ok(s) = std::str::from_utf8(&data[offset+2..offset+2+len]) {
                        let t = s.trim_matches('\0');
                        if !t.is_empty() { ssid = t.to_string(); }
                    }
                    if ssid.is_empty() { ssid = "<hidden>".to_string(); }
                }
                3 => {
                    if len >= 1 {
                        channel = data[offset + 2];
                    }
                }
                48 => {
                    if len >= 2 {
                        let mut ver = u16::from_le_bytes([data[offset+2], data[offset+3]]);
                        if len >= 3 {
                            let gc = data[offset+4] as u32;
                            let akms_start = offset + 7;
                            let akms_len = if len >= 5 { data[offset+6] as usize } else { 0 };
                            if akms_start + akms_len <= data.len() {
                                for i in 0..akms_len {
                                    if akms_start + i*2 + 1 < data.len() {
                                        let akm = u16::from_le_bytes([data[akms_start + i*2], data[akms_start + i*2 + 1]]);
                                        if akm == 2 || akm == 3 || akm == 4 { ver = 0x10; }
                                        if akm == 8 { ver = 0x20; }
                                    }
                                }
                            }
                            _ = gc;
                        }
                        match ver & 0xFF {
                            0x10 => encryption = if encryption.is_empty() { "WPA2".to_string() } else { format!("{}+WPA2", encryption) },
                            0x20 => encryption = if encryption.is_empty() { "WPA3".to_string() } else { format!("{}+WPA3", encryption) },
                            1 => encryption = if encryption.is_empty() { "WPA".to_string() } else { format!("{}+WPA", encryption) },
                            _ => { if encryption.is_empty() { encryption = "WEP".to_string(); } }
                        }
                        if encryption.is_empty() { encryption = "WEP".to_string(); }
                    }
                }
                61 => {
                    if len >= 1 {
                        let wps_state = data[offset + 2];
                        if wps_state == 0x01 || len >= 5 {
                            wps = true;
                        }
                    }
                }
                _ => {}
            }

            if id == 0 {
                if ssid.is_empty() { ssid = "<hidden>".to_string(); }
                if encryption.is_empty() { encryption = "OPN".to_string(); }
                break;
            }
            offset += 2 + len;
        }
        (ssid, channel, encryption, wps)
    }

    fn extract_probes(&self, data: &[u8], hdr: usize) -> Vec<String> {
        let mut probes = Vec::new();
        let mut offset = hdr + 24usize;
        loop {
            if offset + 2 > data.len() { break; }
            let id = data[offset];
            let len = data[offset + 1] as usize;
            if offset + 2 + len > data.len() { break; }
            if id == 0 && len > 0 {
                if let Ok(s) = std::str::from_utf8(&data[offset+2..offset+2+len]) {
                    let t = s.trim_matches('\0');
                    if !t.is_empty() { probes.push(t.to_string()); }
                }
            }
            if id == 0 { break; }
            offset += 2 + len;
        }
        probes
    }

    pub fn print_table(&self, ch: u8, elapsed: Duration) {
        let mut ap_sorted: Vec<&ApEntry> = self.aps.values().collect();
        ap_sorted.sort_by(|a, b| b.beacons.cmp(&a.beacons));

        let mut station_sorted: Vec<&StationEntry> = self.stations.values().collect();
        station_sorted.sort_by(|a, b| b.packets.cmp(&a.packets));

        // Clear screen
        print!("\x1B[2J\x1B[H");

        println!("\x1b[1;36m╔══════════════════════════════════════════════════════════════════════════════════════╗\x1b[0m");
        println!("\x1b[1;36m║                              HACKIT AIRODUMP-NG                                   ║\x1b[0m");
        println!("\x1b[1;36m╠══════════════════════════════════════════════════════════════════════════════════════╣\x1b[0m");
        println!("\x1b[1;36m║\x1b[0m  Channel: {:<3}  |  APs: {:<4}  |  Stations: {:<4}  |  Elapsed: {:<8}            \x1b[1;36m║\x1b[0m",
            ch, self.aps.len(), self.stations.len(), format_elapsed(elapsed));
        println!("\x1b[1;36m╚══════════════════════════════════════════════════════════════════════════════════════╝\x1b[0m");
        println!();

        // AP table
        println!("\x1b[1;33m  ACCESS POINTS ({})\x1b[0m", ap_sorted.len());
        println!("\x1b[90m  {:<5} {:<32} {:<18} {:<4} {:<7} {:<6} {:<10} {:<5} {}\x1b[0m",
            "PWR", "SSID", "BSSID", "CH", "ENC", "CIPHER", "VENDOR", "WPS", "#");
        for (i, ap) in ap_sorted.iter().enumerate() {
            if i >= 40 { break; }
            let (pwr_str, pwr_color) = signal_bar(ap.signal);
            let enc_str = format!("{:6}", ap.encryption);
            let wps_str = if ap.wps { "\x1b[32mYES\x1b[0m" } else { "\x1b[90mNO \x1b[0m" };
            if ap.ssid == "<hidden>" {
                println!("  {}{:<5}{}\x1b[0m \x1b[3;90m{:<32}\x1b[0m {:<18} {:<4} {} {:6} {:<10} {} {:4}",
                    pwr_color, pwr_str, "\x1b[0m",
                    "<length 0>", ap.bssid, ap.channel, enc_str, "", ap.vendor, wps_str, ap.beacons);
            } else {
                let ssid_trim = if ap.ssid.len() > 31 { format!("{}…", &ap.ssid[..30]) } else { ap.ssid.clone() };
                println!("  {}{:<5}{}\x1b[0m {:<32} {:<18} CH{:<2} {} {:6} {:<10} {} {:4}",
                    pwr_color, pwr_str, "\x1b[0m",
                    ssid_trim, ap.bssid, ap.channel, enc_str, "", ap.vendor, wps_str, ap.beacons);
            }
        }
        println!();

        // Station table
        println!("\x1b[1;34m  STATIONS ({})\x1b[0m", station_sorted.len());
        println!("\x1b[90m  {:<5} {:<18} {:<18} {:<8} {:<32} {}\x1b[0m",
            "PWR", "STATION MAC", "BSSID", "PACKETS", "PROBES", "#");
        for (i, sta) in station_sorted.iter().enumerate() {
            if i >= 30 { break; }
            let (pwr_str, pwr_color) = signal_bar(sta.signal);
            let bssid = if sta.bssid.len() == 17 { sta.bssid.clone() } else { "(not associated)".to_string() };
            let probes = if sta.probes.is_empty() {
                String::new()
            } else {
                sta.probes.join(", ")
            };
            let probes_trim = if probes.len() > 31 { format!("{}…", &probes[..30]) } else { probes };
            println!("  {}{:<5}{}\x1b[0m {:<18} {:<18} {:8} {:<32}",
                pwr_color, pwr_str, "\x1b[0m",
                sta.mac, bssid, sta.packets, probes_trim);
        }
        println!();
    }
}

fn signal_bar(signal: i16) -> (String, String) {
    let color = if signal > -50 { "\x1b[32m" }
                else if signal > -70 { "\x1b[33m" }
                else { "\x1b[31m" };
    let bars = if signal > -50 { "████"
               } else if signal > -60 { "███▌"
               } else if signal > -70 { "██▌"
               } else if signal > -80 { "█▌"
               } else { "▌" };
    (format!("{}{}", bars, signal), color.to_string())
}

fn format_elapsed(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 { format!("{}s", secs) }
    else { format!("{}m{:02}s", secs / 60, secs % 60) }
}
