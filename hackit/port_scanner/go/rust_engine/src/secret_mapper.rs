/*
 * HackIT Secret Intelligence Mapper (Rust)
 * Detects hidden metadata, leaked secrets, and system-specific hints.
 */

pub struct SecretIntel {
    pub keys_found: Vec<String>,
    pub metadata: Vec<String>,
}

pub fn map_secret_intelligence(banner: &str) -> SecretIntel {
    let mut intel = SecretIntel {
        keys_found: Vec::new(),
        metadata: Vec::new(),
    };

    // Pattern matching for "Secret" hints
    if banner.contains("X-Powered-By") {
        intel.metadata.push("Tech Stack leakage in HTTP headers".to_string());
    }
    if banner.contains("INTERNAL") || banner.contains("10.") || banner.contains("192.168.") {
        intel.metadata.push("Internal network addressing exposed".to_string());
    }
    if banner.contains("AKIA") || banner.contains("AIza") {
        intel.keys_found.push("Potential AWS/Google API Key signature detected".to_string());
    }

    intel
}

#[no_mangle]
pub unsafe extern "C" fn rust_map_secrets(banner: *const std::os::raw::c_char) -> *mut std::os::raw::c_char {
    let c_banner = std::ffi::CStr::from_ptr(banner).to_str().unwrap_or("");
    let intel = map_secret_intelligence(c_banner);
    
    let mut output = String::new();
    for m in intel.metadata {
        output.push_str(&format!("META:{}|", m));
    }
    for k in intel.keys_found {
        output.push_str(&format!("KEY:{}|", k));
    }
    
    std::ffi::CString::new(output).unwrap().into_raw()
}
