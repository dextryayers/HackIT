use std::ffi::CStr;
use std::slice;
use tracing::{debug, info};
use crate::packet_parser;

pub struct PacketEngine;

impl PacketEngine {
    pub fn new() -> Self {
        PacketEngine
    }

    /// This is the C callback that libpcap will call for every packet.
    pub extern "C" fn handle_packet_c(
        _user: *mut libc::c_uchar,
        pkthdr: *const crate::c_bindings::pcap_pkthdr,
        packet: *const libc::c_uchar,
    ) {
        if packet.is_null() || pkthdr.is_null() {
            return;
        }

        // Safely convert raw C bytes into a Rust slice based on capture length
        let length = unsafe { (*pkthdr).caplen };
        let packet_slice = unsafe { slice::from_raw_parts(packet, length as usize) };
        
        Self::process_packet(packet_slice);
    }

    /// Decode raw frame bytes and serialize parsed parameters as dynamic JSON telemetry
    fn process_packet(packet: &[u8]) {
        if let Some(frame) = packet_parser::decode_binary_frame(packet) {
            let event_json = if let Some(step) = frame.eapol_step {
                format!(
                    r#"{{"event": "eapol_handshake", "bssid": "{}", "step": {}, "size": {}}}"#,
                    frame.bssid.unwrap_or_default(),
                    step,
                    frame.size
                )
            } else if frame.frame_type == "IEEE 802.11 Beacon" {
                format!(
                    r#"{{"event": "beacon", "bssid": "{}", "ssid": "{}", "size": {}}}"#,
                    frame.bssid.unwrap_or_default(),
                    frame.ssid.unwrap_or_else(|| "N/A".to_string()),
                    frame.size
                )
            } else {
                format!(
                    r#"{{"event": "qos_data", "bssid": "{}", "size": {}}}"#,
                    frame.bssid.unwrap_or_default(),
                    frame.size
                )
            };

            // Capture via stdout subprocess pipe
            println!("{}", event_json);
        }
    }
}
