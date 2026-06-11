use std::convert::TryInto;

#[derive(Debug, Clone)]
pub struct SaeCommit {
    pub scalar: [u8; 32],
    pub element: [u8; 32],
    pub send_addr: [u8; 6],
}

#[derive(Debug, Clone)]
pub struct SaeConfirm {
    pub send_addr: [u8; 6],
    pub transaction_seq: u16,
    pub confirm: [u8; 32],
}

const SAE_AUTH_TYPE_COMMIT: u16 = 1;
const SAE_AUTH_TYPE_CONFIRM: u16 = 2;
const WLAN_IE_RSN_TAG: u8 = 48;
const RSN_AKM_SAE: [u8; 4] = [0x00, 0x0F, 0xAC, 0x08];
const RSN_AKM_FT_SAE: [u8; 4] = [0x00, 0x0F, 0xAC, 0x09];

fn read_u16_be(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > data.len() {
        return None;
    }
    Some(u16::from_be_bytes([data[offset], data[offset + 1]]))
}

fn read_u32_be(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > data.len() {
        return None;
    }
    Some(u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

fn copy_bytes<const N: usize>(data: &[u8], offset: usize) -> Option<[u8; N]> {
    if offset + N > data.len() {
        return None;
    }
    data[offset..offset + N]
        .try_into()
        .ok()
}

pub fn detect_wpa3(frame: &[u8]) -> bool {
    if frame.len() < 24 {
        return false;
    }

    let frame_type = (frame[0] >> 2) & 0x03;
    let frame_subtype = (frame[0] >> 4) & 0x0F;
    if frame_type != 0 || frame_subtype != 8 {
        return false;
    }

    let mut offset = 24;
    let fixed_params_len = 12;
    if offset + fixed_params_len > frame.len() {
        return false;
    }

    let capability_info = match read_u16_be(frame, offset + 10) {
        Some(v) => v,
        None => return false,
    };
    let _ = capability_info;
    offset += fixed_params_len;

    while offset + 2 <= frame.len() {
        let tag_number = frame[offset];
        let tag_len = frame[offset + 1] as usize;
        offset += 2;

        if offset + tag_len > frame.len() {
            break;
        }

        if tag_number == WLAN_IE_RSN_TAG {
            if detect_sae_in_rsn(&frame[offset..offset + tag_len]) {
                return true;
            }
        }

        offset += tag_len;
    }

    false
}

fn detect_sae_in_rsn(rsn_data: &[u8]) -> bool {
    if rsn_data.len() < 2 {
        return false;
    }

    let rsn_version = read_u16_be(rsn_data, 0).unwrap_or(0);
    if rsn_version != 1 {
        return false;
    }

    let mut offset = 2;

    offset += 4; // skip group cipher suite

    if offset + 2 > rsn_data.len() {
        return false;
    }
    let pairwise_count = read_u16_be(rsn_data, offset).unwrap_or(0) as usize;
    offset += 2;
    offset += pairwise_count * 4;

    if offset + 2 > rsn_data.len() {
        return false;
    }
    let akm_count = read_u16_be(rsn_data, offset).unwrap_or(0) as usize;
    offset += 2;

    for _ in 0..akm_count {
        if offset + 4 > rsn_data.len() {
            break;
        }
        let akm_suite = &rsn_data[offset..offset + 4];
        if akm_suite == RSN_AKM_SAE || akm_suite == RSN_AKM_FT_SAE {
            return true;
        }
        offset += 4;
    }

    false
}

pub fn build_sae_auth_frame(bssid: &str, client_mac: &str) -> Option<Vec<u8>> {
    let bssid_bytes = parse_mac(bssid)?;
    let client_bytes = parse_mac(client_mac)?;

    let mut frame = Vec::with_capacity(64);

    frame.push(0xB0); // Type: Management (00), Subtype: Authentication (1011)
    frame.push(0x00); // Flags

    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // Destination: broadcast
    frame.extend_from_slice(&bssid_bytes); // Source
    frame.extend_from_slice(&bssid_bytes); // BSSID

    frame.push(0x00); // Sequence control (fragment 0)
    frame.push(0x00);

    frame.extend_from_slice(&client_bytes); // Auth algorithm: SAE (3)

    frame.extend_from_slice(&SAE_AUTH_TYPE_COMMIT.to_be_bytes()); // Auth seq: 1 (Commit)
    frame.extend_from_slice(&[0x00, 0x00]); // Status: success

    Some(frame)
}

pub fn parse_sae_commit(frame: &[u8]) -> Option<SaeCommit> {
    if frame.len() < 38 {
        return None;
    }

    let frame_type = (frame[0] >> 2) & 0x03;
    let frame_subtype = (frame[0] >> 4) & 0x0F;
    if frame_type != 0 || frame_subtype != 11 {
        return None;
    }

    let mut offset = 24;

    let auth_algo = read_u16_be(frame, offset).unwrap_or(0);
    if auth_algo != 3 {
        return None;
    }
    offset += 2;

    let auth_seq = read_u16_be(frame, offset).unwrap_or(0);
    if auth_seq != SAE_AUTH_TYPE_COMMIT {
        return None;
    }
    offset += 2;

    let _status = read_u16_be(frame, offset).unwrap_or(0);
    offset += 2;

    let send_addr = copy_bytes::<6>(frame, 4)?;
    let scalar = copy_bytes::<32>(frame, offset)?;
    offset += 32;

    let element = copy_bytes::<32>(frame, offset)?;

    Some(SaeCommit {
        scalar,
        element,
        send_addr,
    })
}

pub fn parse_sae_confirm(frame: &[u8]) -> Option<SaeConfirm> {
    if frame.len() < 42 {
        return None;
    }

    let frame_type = (frame[0] >> 2) & 0x03;
    let frame_subtype = (frame[0] >> 4) & 0x0F;
    if frame_type != 0 || frame_subtype != 11 {
        return None;
    }

    let mut offset = 24;

    let auth_algo = read_u16_be(frame, offset).unwrap_or(0);
    if auth_algo != 3 {
        return None;
    }
    offset += 2;

    let auth_seq = read_u16_be(frame, offset).unwrap_or(0);
    if auth_seq != SAE_AUTH_TYPE_CONFIRM {
        return None;
    }
    offset += 2;

    let _status = read_u16_be(frame, offset).unwrap_or(0);
    offset += 2;

    let send_addr = copy_bytes::<6>(frame, 4)?;
    let transaction_seq = read_u16_be(frame, offset)?;
    offset += 2;

    let confirm = copy_bytes::<32>(frame, offset)?;

    Some(SaeConfirm {
        send_addr,
        transaction_seq,
        confirm,
    })
}

fn parse_mac(mac_str: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return None;
    }

    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return None;
        }
        bytes[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac_valid() {
        let mac = parse_mac("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_parse_mac_invalid() {
        assert!(parse_mac("invalid").is_none());
        assert!(parse_mac("AA:BB:CC:DD:EE").is_none());
        assert!(parse_mac("AA:BB:CC:DD:EE:FF:00").is_none());
    }

    #[test]
    fn test_detect_wpa3_short_frame() {
        assert!(!detect_wpa3(&[0u8; 10]));
    }

    #[test]
    fn test_parse_sae_commit_short_frame() {
        assert!(parse_sae_commit(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_parse_sae_confirm_short_frame() {
        assert!(parse_sae_confirm(&[0u8; 10]).is_none());
    }
}
