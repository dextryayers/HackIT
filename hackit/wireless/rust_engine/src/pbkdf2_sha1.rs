struct Sha1 {
    h: [u32; 5],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha1 {
    fn new() -> Self {
        Sha1 {
            h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        if self.buf_len > 0 {
            let space = 64 - self.buf_len;
            let take = data.len().min(space);
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            offset += take;
            if self.buf_len == 64 {
                self.process_block();
                self.buf_len = 0;
            }
        }
        while offset + 64 <= data.len() {
            self.buf.copy_from_slice(&data[offset..offset + 64]);
            self.process_block();
            offset += 64;
        }
        if offset < data.len() {
            let rem = data.len() - offset;
            self.buf[..rem].copy_from_slice(&data[offset..]);
            self.buf_len = rem;
        }
        self.total_len += data.len() as u64;
    }

    fn digest(mut self) -> [u8; 20] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0x00]);
        }
        let len_bytes = bit_len.to_be_bytes();
        self.update(&len_bytes);
        let mut result = [0u8; 20];
        for (i, &h) in self.h.iter().enumerate() {
            result[i * 4..i * 4 + 4].copy_from_slice(&h.to_be_bytes());
        }
        result
    }

    fn process_block(&mut self) {
        let mut w = [0u32; 80];
        for t in 0..16 {
            w[t] = u32::from_be_bytes([
                self.buf[t * 4],
                self.buf[t * 4 + 1],
                self.buf[t * 4 + 2],
                self.buf[t * 4 + 3],
            ]);
        }
        for t in 16..80 {
            w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];

        for t in 0..80 {
            let (f, k): (u32, u32) = if t < 20 {
                ((b & c) | (!b & d), 0x5A827999)
            } else if t < 40 {
                (b ^ c ^ d, 0x6ED9EBA1)
            } else if t < 60 {
                ((b & c) | (b & d) | (c & d), 0x8F1BBCDC)
            } else {
                (b ^ c ^ d, 0xCA62C1D6)
            };
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[t]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }
}

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut ctx = Sha1::new();
    ctx.update(data);
    ctx.digest()
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let k: [u8; 64] = if key.len() > 64 {
        let hashed = sha1(key);
        let mut padded = [0u8; 64];
        padded[..20].copy_from_slice(&hashed);
        padded
    } else if key.len() < 64 {
        let mut padded = [0u8; 64];
        padded[..key.len()].copy_from_slice(key);
        padded
    } else {
        let mut fixed = [0u8; 64];
        fixed.copy_from_slice(&key[..64]);
        fixed
    };

    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for i in 0..64 {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }

    let mut inner = Vec::with_capacity(64 + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let inner_hash = sha1(&inner);

    let mut outer = Vec::with_capacity(64 + 20);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha1(&outer)
}

fn pbkdf2_f(pwd: &[u8], salt: &[u8], iterations: u32, block: u32) -> [u8; 20] {
    let mut salt_block = Vec::with_capacity(salt.len() + 4);
    salt_block.extend_from_slice(salt);
    salt_block.extend_from_slice(&block.to_be_bytes());

    let mut u = hmac_sha1(pwd, &salt_block);
    let mut result = u;

    for _ in 1..iterations {
        u = hmac_sha1(pwd, &u);
        for j in 0..20 {
            result[j] ^= u[j];
        }
    }
    result
}

fn pbkdf2_sha1(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    let blocks = (dk_len + 19) / 20;
    let mut result = Vec::with_capacity(dk_len);
    for i in 1..=blocks {
        let block = pbkdf2_f(password, salt, iterations, i as u32);
        result.extend_from_slice(&block);
    }
    result.truncate(dk_len);
    result
}

fn prf_80211(key: &[u8], prefix: &[u8], data: &[u8], length: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(length);
    let mut i: u8 = 0;
    while result.len() < length {
        let mut msg = Vec::new();
        msg.extend_from_slice(prefix);
        msg.push(0x00);
        msg.extend_from_slice(data);
        msg.push(i);
        let h = hmac_sha1(key, &msg);
        result.extend_from_slice(&h);
        i = i.wrapping_add(1);
    }
    result.truncate(length);
    result
}

pub fn compute_pmk(password: &str, ssid: &str) -> [u8; 32] {
    let pwd = password.as_bytes();
    let salt = ssid.as_bytes();
    let dk = pbkdf2_sha1(pwd, salt, 4096, 32);
    let mut pmk = [0u8; 32];
    pmk.copy_from_slice(&dk);
    pmk
}

pub fn compute_pmkid(pmk: &[u8; 32], ap_mac: &[u8; 6], client_mac: &[u8; 6]) -> [u8; 16] {
    let pmk_name: [u8; 4] = [0x00, 0x50, 0xF2, 0x59];
    let mut data = Vec::with_capacity(4 + 6 + 6);
    data.extend_from_slice(&pmk_name);
    data.extend_from_slice(ap_mac);
    data.extend_from_slice(client_mac);
    let h = hmac_sha1(pmk, &data);
    let mut pmkid = [0u8; 16];
    pmkid.copy_from_slice(&h[..16]);
    pmkid
}

pub fn verify_wpa_handshake(eapol_data: &[u8], pmk: &[u8; 32]) -> bool {
    if eapol_data.len() < 95 {
        return false;
    }

    let key_info = u16::from_be_bytes([eapol_data[5], eapol_data[6]]);
    let key_desc = eapol_data[4];

    let is_wpa2 = key_desc == 0x02;
    let key_len = if is_wpa2 { 16 } else { 32 };

    if eapol_data.len() < 77 + key_len {
        return false;
    }

    let anonce = &eapol_data[13..13 + 32];
    let snonce_pos = 13 + 32;
    let snonce = &eapol_data[snonce_pos..snonce_pos + 32];
    let key_mic_start = 77 + key_len;
    if key_mic_start + 16 > eapol_data.len() {
        return false;
    }

    let mut stored_mic = [0u8; 16];
    stored_mic.copy_from_slice(&eapol_data[key_mic_start..key_mic_start + 16]);

    let akm = (key_info >> 3) & 0x07;
    let kck_len = match akm {
        1 | 2 => 16,
        _ => 16,
    };

    let ap_mac = &eapol_data[10..16];
    let sta_mac = &eapol_data[22..28];

    let data_for_prf = {
        let mac_a = ap_mac.min(sta_mac);
        let mac_b = ap_mac.max(sta_mac);
        let nonce_a = anonce.min(snonce);
        let nonce_b = anonce.max(snonce);

        let mut d = Vec::new();
        d.extend_from_slice(nonce_a);
        d.extend_from_slice(nonce_b);
        d.extend_from_slice(mac_a);
        d.extend_from_slice(mac_b);
        d
    };

    let ptk = prf_80211(
        pmk,
        b"Pairwise key expansion",
        &data_for_prf,
        16 + 16 + 16 + 8,
    );

    let kck = &ptk[..kck_len];

    let mut eapol_zeroed = eapol_data.to_vec();
    let mic_offset = key_mic_start;
    for j in 0..16 {
        if mic_offset + j < eapol_zeroed.len() {
            eapol_zeroed[mic_offset + j] = 0;
        }
    }

    let computed_mic = hmac_sha1(kck, &eapol_zeroed);
    computed_mic[..16] == stored_mic
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_basic() {
        let digest = sha1(b"abc");
        assert_eq!(digest.len(), 20);
        let expected = [
            0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A,
            0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C,
            0x9C, 0xD0, 0xD8, 0x9D,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha1_empty() {
        let digest = sha1(b"");
        let expected = [
            0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D,
            0x32, 0x55, 0xBF, 0xEF, 0x95, 0x60, 0x18, 0x90,
            0xAF, 0xD8, 0x07, 0x09,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_hmac_sha1_rfc2202() {
        let key = b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
        let data = b"Hi There";
        let h = hmac_sha1(key, data);
        let expected = [
            0xB6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64,
            0xE2, 0x8B, 0xC0, 0xB6, 0xFB, 0x37, 0x8C, 0x8E,
            0xF1, 0x46, 0xBE, 0x00,
        ];
        assert_eq!(h, expected);
    }

    #[test]
    fn test_pmk_computation() {
        let pmk = compute_pmk("password", "test");
        assert_eq!(pmk.len(), 32);
    }

    #[test]
    fn test_pmkid_computation() {
        let pmk = compute_pmk("testpsk", "TestSSID");
        let ap_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let client_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let pmkid = compute_pmkid(&pmk, &ap_mac, &client_mac);
        assert_eq!(pmkid.len(), 16);
    }

    #[test]
    fn test_pbkdf2_known() {
        let dk = pbkdf2_sha1(b"password", b"salt", 1, 20);
        let expected = [
            0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
            0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
            0x2f, 0xe0, 0x37, 0xa6,
        ];
        assert_eq!(dk, expected);
    }

    #[test]
    fn test_pbkdf2_4096() {
        let dk = pbkdf2_sha1(b"password", b"salt", 4096, 20);
        assert_eq!(dk.len(), 20);
    }
}
