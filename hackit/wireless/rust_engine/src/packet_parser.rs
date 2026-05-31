pub struct DecodedFrame {
    pub frame_type: String,
    pub bssid: Option<String>,
    pub ssid: Option<String>,
    pub size: usize,
    pub eapol_step: Option<u8>,
}

pub fn decode_binary_frame(payload: &[u8]) -> Option<DecodedFrame> {
    if payload.len() < 24 {
        return None;
    }

    let fc = payload[0];
    let frame_type_bits = (fc & 0x0C) >> 2;
    let subtype_bits = (fc & 0xFC) >> 4;

    // Check if EAPOL header matches standard offsets (FC=0x08, payload[31]==3 for EAPOL Key)
    if frame_type_bits == 0 && payload.len() >= 34 && payload[31] == 0x03 {
        let bssid = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            payload[10], payload[11], payload[12], payload[13], payload[14], payload[15]
        );
        let step = payload[33];
        Some(DecodedFrame {
            frame_type: "EAPOL 4-Way Handshake".to_string(),
            bssid: Some(bssid),
            ssid: None,
            size: payload.len(),
            eapol_step: Some(step),
        })
    } else if frame_type_bits == 0 && subtype_bits == 8 {
        // Beacon frame
        let bssid = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            payload[10], payload[11], payload[12], payload[13], payload[14], payload[15]
        );
        
        let mut ssid = None;
        if payload.len() > 38 && payload[36] == 0 {
            let ssid_len = payload[37] as usize;
            if payload.len() >= 38 + ssid_len {
                if let Ok(ssid_str) = std::str::from_utf8(&payload[38..38 + ssid_len]) {
                    ssid = Some(ssid_str.to_string());
                }
            }
        }

        Some(DecodedFrame {
            frame_type: "IEEE 802.11 Beacon".to_string(),
            bssid: Some(bssid),
            ssid,
            size: payload.len(),
            eapol_step: None,
        })
    } else if frame_type_bits == 2 && subtype_bits == 8 {
        // QoS Data Frame
        let bssid = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            payload[10], payload[11], payload[12], payload[13], payload[14], payload[15]
        );
        Some(DecodedFrame {
            frame_type: "IEEE 802.11 QoS Data".to_string(),
            bssid: Some(bssid),
            ssid: None,
            size: payload.len(),
            eapol_step: None,
        })
    } else {
        None
    }
}
