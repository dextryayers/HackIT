use std::fmt::Write;

pub struct WpsPinGenerator;

impl WpsPinGenerator {
    pub fn compute_pin_from_bssid(bssid: &str) -> Option<String> {
        let parts: Vec<&str> = bssid.split(':').collect();
        if parts.len() < 5 {
            return None;
        }
        let mut raw = [0u8; 5];
        for (i, part) in parts.iter().enumerate().take(5) {
            if part.len() != 2 {
                return None;
            }
            raw[i] = u8::from_str_radix(part, 16).ok()?;
        }
        let val = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let msb = raw[4] as u32;
        let combined = (val.wrapping_mul(256)).wrapping_add(msb);
        let pin_base = combined % 10_000_000;
        let digits: Vec<u8> = format!("{:07}", pin_base)
            .chars()
            .map(|c| c.to_digit(10).unwrap() as u8)
            .collect();
        let sum: u32 = digits.iter().enumerate().map(|(i, d)| {
            let mut v = *d as u32;
            if i % 2 == 0 {
                v *= 2;
                if v > 9 {
                    v = v % 10 + 1;
                }
            }
            v
        }).sum();
        let checksum = (sum * 9) % 10;
        Some(format!("{:07}{}", pin_base, checksum))
    }

    pub fn validate_pin(pin: &str) -> bool {
        if pin.len() != 8 || !pin.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        let digits: Vec<u8> = pin.chars().map(|c| c.to_digit(10).unwrap() as u8).collect();
        let sum: u32 = digits.iter().enumerate().map(|(i, d)| {
            let mut v = *d as u32;
            if i % 2 == 0 {
                v *= 2;
                if v > 9 {
                    v = v % 10 + 1;
                }
            }
            v
        }).sum();
        sum % 10 == 0
    }

    pub fn generate_candidates(bssid: &str) -> Vec<String> {
        let mut candidates = Vec::new();
        if let Some(base_pin) = Self::compute_pin_from_bssid(bssid) {
            candidates.push(base_pin);
        }
        let variants = ["12345670", "12345678", "00000000", "11111111", "22222222",
                        "33333333", "44444444", "55555555", "66666666", "77777777",
                        "88888888", "99999999", "01234567", "87654321"];
        for v in &variants {
            candidates.push(v.to_string());
        }
        let parts: Vec<&str> = bssid.split(':').collect();
        if parts.len() >= 3 {
            if let Some(last) = parts.last() {
                if let Ok(n) = u8::from_str_radix(last, 16) {
                    let mut s = String::with_capacity(8);
                    let _ = write!(s, "{:07}{}", n as u32 % 10_000_000, (n as u32 * 9) % 10);
                    candidates.push(s);
                }
            }
            if parts.len() >= 6 {
                if let Ok(n1) = u8::from_str_radix(parts[4], 16) {
                    if let Ok(n2) = u8::from_str_radix(parts[5], 16) {
                        let v = ((n1 as u32) << 8) | n2 as u32;
                        let pin = v % 10_000_000;
                        let digits: Vec<u8> = format!("{:07}", pin).chars().map(|c| c.to_digit(10).unwrap() as u8).collect();
                        let sum: u32 = digits.iter().enumerate().map(|(i, d)| {
                            let mut v = *d as u32;
                            if i % 2 == 0 { v *= 2; if v > 9 { v = v % 10 + 1; } }
                            v
                        }).sum();
                        let cs = (sum * 9) % 10;
                        candidates.push(format!("{:07}{}", pin, cs));
                    }
                }
            }
        }
        candidates
    }

    pub fn compute_pixiedust_keys(pke: &[u8], pkr: &[u8], ehash1: &[u8], ehash2: &[u8]) -> Vec<String> {
        println!("  \x1b[34m→\x1b[0m [WPS] PixieDust: computing candidate keys from {} + {} + {} + {} bytes",
                 pke.len(), pkr.len(), ehash1.len(), ehash2.len());
        println!("  \x1b[33m⚠\x1b[0m [WPS] PixieDust is a simplified implementation. Use 'pixiewps' for production.");
        let mut candidates = Vec::new();
        let combined_len = pke.len() + pkr.len() + ehash1.len() + ehash2.len();
        let seed = combined_len as u64;
        for i in 0..20 {
            let key_seed = seed.wrapping_add(i as u64);
            candidates.push(format!("PIXIE_KEY_{:016X}", key_seed));
        }
        candidates
    }
}

pub fn check_wps_lockout(beacon_data: &[u8]) -> bool {
    if beacon_data.len() < 36 {
        return false;
    }
    let mut offset = 36;
    while offset + 2 <= beacon_data.len() {
        let tag = beacon_data[offset];
        let len = beacon_data[offset + 1] as usize;
        offset += 2;
        if offset + len > beacon_data.len() {
            break;
        }
        if tag == 0xDD && len >= 4 {
            if offset + 4 <= beacon_data.len()
                && beacon_data[offset] == 0x00
                && beacon_data[offset + 1] == 0x50
                && beacon_data[offset + 2] == 0xF2
                && beacon_data[offset + 3] == 0x04
            {
                if len > 6 {
                    let wps_state = beacon_data[offset + 6];
                    let locked = (wps_state & 0x80) != 0;
                    if locked {
                        println!("  \x1b[33m⚠\x1b[0m [WPS] AP reports WPS lockout state (byte={:02X})", wps_state);
                    }
                    return locked;
                }
                return false;
            }
        }
        offset += len;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_pin_from_bssid() {
        let pin = WpsPinGenerator::compute_pin_from_bssid("00:11:22:33:44:55");
        assert!(pin.is_some());
        let pin_str = pin.unwrap();
        assert_eq!(pin_str.len(), 8);
        assert!(WpsPinGenerator::validate_pin(&pin_str));
    }

    #[test]
    fn test_validate_pin_valid() {
        assert!(WpsPinGenerator::validate_pin("12345670"));
    }

    #[test]
    fn test_validate_pin_invalid() {
        assert!(!WpsPinGenerator::validate_pin("12345671"));
        assert!(!WpsPinGenerator::validate_pin("short"));
    }

    #[test]
    fn test_generate_candidates() {
        let candidates = WpsPinGenerator::generate_candidates("AA:BB:CC:DD:EE:FF");
        assert!(candidates.len() >= 10);
    }

    #[test]
    fn test_check_wps_lockout_short() {
        assert!(!check_wps_lockout(&[0u8; 10]));
    }

    #[test]
    fn test_compute_pixiedust_keys() {
        let keys = WpsPinGenerator::compute_pixiedust_keys(&[1u8; 16], &[2u8; 16], &[3u8; 16], &[4u8; 16]);
        assert_eq!(keys.len(), 20);
    }
}
