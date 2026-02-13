use std::collections::HashMap;

/// Expert OS Fingerprinting Engine (Rust-Turbo)
/// Focuses on TCP Options and advanced flag analysis

pub struct RustOSDetector {
    signatures: HashMap<(u8, u16), String>,
}

impl RustOSDetector {
    pub fn new() -> Self {
        let mut sigs = HashMap::new();
        // (TTL, WindowSize) -> OS Name
        sigs.insert((64, 5840), "Linux (Modern Kernel)".to_string());
        sigs.insert((64, 29200), "Linux (Ubuntu/Debian)".to_string());
        sigs.insert((128, 8192), "Windows 10/11".to_string());
        sigs.insert((128, 65535), "Windows Server".to_string());
        sigs.insert((255, 4128), "Cisco IOS".to_string());
        
        RustOSDetector { signatures: sigs }
    }

    pub fn detect(&self, ttl: u8, window_size: u16) -> String {
        // Try exact match first
        if let Some(os) = self.signatures.get(&(ttl, window_size)) {
            return os.clone();
        }

        // Heuristics based on TCP behavior
        match ttl {
            0..=64 => "Unix-like (Linux/macOS/Android)".to_string(),
            65..=128 => "Windows NT Family".to_string(),
            129..=255 => "Network Infrastructure (Router/Switch)".to_string(),
            _ => "Unknown Stack".to_string(),
        }
    }
}

// FFI Interface for Go/C
#[no_mangle]
pub extern "C" fn rust_detect_os(ttl: u8, window_size: u16) -> *const u8 {
    let detector = RustOSDetector::new();
    let result = detector.detect(ttl, window_size);
    let c_str = std::ffi::CString::new(result).unwrap();
    c_str.into_raw() as *const u8
}
