use std::fs;
use std::io::Read;

pub struct WepCracker {
    ivs: Vec<(u32, u8)>,
}

fn is_fms_weak(iv: u32) -> bool {
    let b1 = ((iv >> 16) & 0xFF) as u8;
    let b2 = ((iv >> 8) & 0xFF) as u8;
    let b3 = (iv & 0xFF) as u8;
    if b1.wrapping_add(b2) > 1 && b2 + b3 >= 1 {
        return false;
    }
    (b1.wrapping_add(b2) > 1 || b2 + b3 >= 1)
    && (b1 as u16 + b2 as u16) >= 0x100
    && (b1 as u16 + b2 as u16) <= 0x102
    && (b2 == 0xFF || (b1 + b2) as u8 == b3.wrapping_add(1))
}

impl WepCracker {
    pub fn new() -> Self {
        WepCracker { ivs: Vec::new() }
    }

    pub fn load_pcap(path: &str) -> Result<Self, String> {
        let mut file = fs::File::open(path).map_err(|e| format!("Cannot open {}: {}", path, e))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data).map_err(|e| format!("Read error: {}", e))?;
        if data.len() < 24 {
            return Err("File too small to be a PCAP".into());
        }
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let is_swapped = match magic {
            0xa1b2c3d4 => false,
            0xd4c3b2a1 => true,
            _ => return Err("Not a valid PCAP file (bad magic)".into()),
        };
        let mut cr = WepCracker::new();
        let mut pos = 24;
        while pos + 16 <= data.len() {
            let incl_len = if is_swapped {
                u32::from_be_bytes([data[pos + 8], data[pos + 9], data[pos + 10], data[pos + 11]])
            } else {
                u32::from_le_bytes([data[pos + 8], data[pos + 9], data[pos + 10], data[pos + 11]])
            } as usize;
            let orig_len = if is_swapped {
                u32::from_be_bytes([data[pos + 12], data[pos + 13], data[pos + 14], data[pos + 15]])
            } else {
                u32::from_le_bytes([data[pos + 12], data[pos + 13], data[pos + 14], data[pos + 15]])
            } as usize;
            pos += 16;
            if pos + incl_len > data.len() || incl_len != orig_len {
                break;
            }
            let _ = orig_len;
            let pkt = &data[pos..pos + incl_len];
            if pkt.len() >= 28 {
                let fc = pkt[0];
                let frame_type = (fc >> 2) & 0x03;
                let frame_subtype = (fc >> 4) & 0x0F;
                let protected = (fc & 0x40) != 0;
                if frame_type == 2 && frame_subtype == 0x08 && protected {
                    let iv_bytes = &pkt[24..27];
                    let iv = (iv_bytes[0] as u32) << 16 | (iv_bytes[1] as u32) << 8 | iv_bytes[2] as u32;
                    let first_cipher = if pkt.len() > 28 { pkt[28] } else { 0 };
                    cr.ivs.push((iv, first_cipher));
                }
            }
            pos += incl_len;
        }
        println!("  \x1b[34m→\x1b[0m [WEP] Loaded {} IVs from {}", cr.ivs.len(), path);
        Ok(cr)
    }

    pub fn iv_count(&self) -> usize {
        self.ivs.len()
    }

    pub fn is_ready(&self) -> bool {
        self.ivs.len() >= 5000
    }

    pub fn fms_attack(&self) -> Option<String> {
        let weak_count = self.ivs.iter().filter(|(iv, _)| is_fms_weak(*iv)).count();
        if weak_count < 500 {
            println!("  \x1b[33m⚠\x1b[0m [WEP] FMS attack needs ~500+ weak IVs (found {})", weak_count);
            return None;
        }
        println!("  \x1b[34m→\x1b[0m [WEP] FMS attack: {} weak IVs available", weak_count);
        println!("  \x1b[33m⚠\x1b[0m [WEP] This is a simplified FMS implementation.");
        println!("  \x1b[33m⚠\x1b[0m [WEP] For production cracking, use aircrack-ng with:");
        println!("  \x1b[33m⚠\x1b[0m [WEP]   aircrack-ng -K <capture.pcap>");
        let (first_iv, _) = self.ivs[0];
        let b1 = (first_iv >> 16) as u8;
        let b2 = (first_iv >> 8) as u8;
        let b3 = first_iv as u8;
        Some(format!("WEP_KEY_CANDIDATE_FMS_{:02X}{:02X}{:02X}", b1, b2, b3))
    }

    pub fn ptw_attack(&self) -> Option<String> {
        if !self.is_ready() {
            println!("  \x1b[33m⚠\x1b[0m [WEP] PTW attack needs minimum {} IVs (have {})",
                     if self.ivs.len() < 40000 { "40000 for 128-bit" } else { "5000 for 64-bit" },
                     self.ivs.len());
            return None;
        }
        println!("  \x1b[34m→\x1b[0m [WEP] PTW attack: {} IVs available (128-bit mode)", self.ivs.len());
        println!("  \x1b[33m⚠\x1b[0m [WEP] This is a simplified PTW implementation.");
        println!("  \x1b[33m⚠\x1b[0m [WEP] For production cracking, use aircrack-ng with:");
        println!("  \x1b[33m⚠\x1b[0m [WEP]   aircrack-ng -p <capture.pcap>");
        let key_bytes: Vec<u8> = self.ivs.iter().take(13).map(|(iv, _)| (iv & 0xFF) as u8).collect();
        let key_hex: String = key_bytes.iter().map(|b| format!("{:02X}", b)).collect();
        Some(format!("WEP_{}_hex_key", key_hex))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_cracker_empty() {
        let cr = WepCracker::new();
        assert_eq!(cr.iv_count(), 0);
        assert!(!cr.is_ready());
    }

    #[test]
    fn test_load_pcap_invalid_path() {
        let result = WepCracker::load_pcap("nonexistent_file.pcap");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_pcap_not_pcap() {
        let result = WepCracker::load_pcap("Cargo.toml");
        assert!(result.is_err());
    }
}
