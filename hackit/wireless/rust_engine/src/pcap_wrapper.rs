#[cfg(feature = "pcap")]
use pcap::{Capture, Device};

pub enum PcapSession {
    #[cfg(feature = "pcap")]
    Real(Capture<pcap::Active>),
    Simulated,
}

pub fn list_devices() -> Vec<String> {
    #[cfg(feature = "pcap")]
    {
        if let Ok(devices) = Device::list() {
            return devices.into_iter().map(|d| d.name).collect();
        }
    }
    Vec::new()
}

pub fn find_device(_name: &str) -> Option<String> {
    #[cfg(feature = "pcap")]
    {
        if let Ok(devices) = Device::list() {
            if devices.iter().any(|d| d.name == _name) {
                return Some(_name.to_string());
            }
        }
    }
    None
}

pub fn open_capture(name: &str) -> Result<PcapSession, String> {
    #[cfg(feature = "pcap")]
    {
        let device = Device::list()
            .map_err(|e| format!("List error: {}", e))?
            .into_iter()
            .find(|d| d.name == name)
            .ok_or_else(|| format!("Interface '{}' not found", name))?;

        let cap = Capture::from_device(device)
            .map_err(|e| format!("Device error: {}", e))?
            .promisc(true)
            .snaplen(65535)
            .timeout(500)
            .open()
            .map_err(|e| format!("Failed to open {}: {}", name, e))?;

        Ok(PcapSession::Real(cap))
    }
    #[cfg(not(feature = "pcap"))]
    {
        println!("[RUST-PCAP] pcap feature disabled. Using simulated capture on {}", name);
        Ok(PcapSession::Simulated)
    }
}

pub fn set_filter(session: &mut PcapSession, _filter_expr: &str) -> bool {
    match session {
        #[cfg(feature = "pcap")]
        PcapSession::Real(cap) => cap.filter(filter_expr, true).is_ok(),
        PcapSession::Simulated => true,
    }
}

pub fn next_packet(session: &mut PcapSession) -> Option<Vec<u8>> {
    match session {
        #[cfg(feature = "pcap")]
        PcapSession::Real(cap) => {
            loop {
                match cap.next_packet() {
                    Ok(pkt) => return Some(pkt.data.to_vec()),
                    Err(pcap::Error::TimeoutExpired) => continue,
                    Err(_) => return None,
                }
            }
        }
        PcapSession::Simulated => {
            None
        }
    }
}

pub fn send_packet(session: &mut PcapSession, data: &[u8]) -> bool {
    match session {
        #[cfg(feature = "pcap")]
        PcapSession::Real(cap) => cap.sendpacket(data).is_ok(),
        PcapSession::Simulated => {
            println!("[RUST-PCAP] Simulated: would send {} bytes", data.len());
            true
        }
    }
}
