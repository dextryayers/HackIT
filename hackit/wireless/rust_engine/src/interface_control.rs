use std::ffi::{CString, CStr};
use std::os::raw::c_char;
use crate::c_bindings;

// Performance optimization: Custom byte scanning instead of heavy regex compilation
pub fn is_valid_mac(mac: &str) -> bool {
    let bytes = mac.as_bytes();
    if bytes.len() != 17 {
        return false;
    }
    for i in 0..17 {
        if i % 3 == 2 {
            if bytes[i] != b':' && bytes[i] != b'-' {
                return false;
            }
        } else {
            let c = bytes[i];
            if !c.is_ascii_hexdigit() {
                return false;
            }
        }
    }
    true
}

pub fn change_mac(interface: &str, new_mac: &str) -> bool {
    if !is_valid_mac(new_mac) {
        eprintln!("[RUST-ENGINE] [ALERT] Invalid MAC address layout: {}", new_mac);
        return false;
    }

    let c_interface = CString::new(interface).expect("CString conversion failed");
    let c_mac = CString::new(new_mac).expect("CString conversion failed");
    unsafe {
        c_bindings::hackit_wifi_change_mac(c_interface.as_ptr(), c_mac.as_ptr())
    }
}

pub fn restore_mac(interface: &str) -> bool {
    let c_interface = CString::new(interface).expect("CString conversion failed");
    unsafe {
        c_bindings::hackit_wifi_restore_mac(c_interface.as_ptr())
    }
}

pub fn set_txpower(interface: &str, value: i32) -> bool {
    if value < 0 || value > 30 {
        eprintln!("[RUST-ENGINE] [ALERT] TxPower value must be between 0 and 30 dBm.");
        return false;
    }
    let c_interface = CString::new(interface).expect("CString conversion failed");
    unsafe {
        c_bindings::hackit_wifi_set_txpower(c_interface.as_ptr(), value)
    }
}

pub fn get_adapter_info(interface: &str) -> String {
    let c_interface = CString::new(interface).expect("CString conversion failed");
    let mut buf = vec![0 as c_char; 4096];
    unsafe {
        if c_bindings::hackit_wifi_get_adapter_info(c_interface.as_ptr(), buf.as_mut_ptr(), 4096) {
            CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()
        } else {
            "[-] Failed to retrieve adapter hardware info.".to_string()
        }
    }
}

pub fn get_status(interface: &str) -> String {
    let c_interface = CString::new(interface).expect("CString conversion failed");
    let mut buf = vec![0 as c_char; 4096];
    unsafe {
        if c_bindings::hackit_wifi_get_status(c_interface.as_ptr(), buf.as_mut_ptr(), 4096) {
            CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()
        } else {
            "[-] Failed to retrieve adapter status.".to_string()
        }
    }
}
