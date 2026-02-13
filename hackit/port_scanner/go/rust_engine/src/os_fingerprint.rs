use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[repr(C)]
pub struct RustOSInfo {
    pub os_name: *mut c_char,
    pub os_version: *mut c_char,
    pub os_family: *mut c_char,
    pub accuracy: i32,
    pub ttl: i32,
}

pub fn detect_os_from_tcp_params(ttl: i32, window_size: i32, banner: &str) -> RustOSInfo {
    let mut os_name = "Unknown";
    let mut os_version = "Unknown";
    let mut os_family = "Unknown";
    let mut accuracy = 50;

    // 1. Heuristic based on TTL (Basic but effective)
    // Linux: 64, Windows: 128, Cisco/Network: 255
    if ttl <= 64 {
        os_family = "Linux/Unix";
        os_name = "Linux";
        accuracy = 60;
    } else if ttl <= 128 {
        os_family = "Windows";
        os_name = "Windows";
        accuracy = 60;
    } else {
        os_family = "Network Device";
        os_name = "Cisco/Generic";
        accuracy = 40;
    }

    // 2. Banner Analysis (Higher Accuracy)
    let banner_lower = banner.to_lowercase();
    if banner_lower.contains("ubuntu") {
        os_name = "Ubuntu";
        os_family = "Linux";
        accuracy = 95;
        if banner_lower.contains("22.04") { os_version = "22.04 LTS"; }
        else if banner_lower.contains("20.04") { os_version = "20.04 LTS"; }
    } else if banner_lower.contains("debian") {
        os_name = "Debian";
        os_family = "Linux";
        accuracy = 95;
    } else if banner_lower.contains("centos") {
        os_name = "CentOS";
        os_family = "Linux";
        accuracy = 90;
    } else if banner_lower.contains("microsoft-iis") {
        os_name = "Windows Server";
        os_family = "Windows";
        accuracy = 85;
        if banner_lower.contains("10.0") { os_version = "2016/2019"; }
        else if banner_lower.contains("8.5") { os_version = "2012 R2"; }
    } else if banner_lower.contains("openssh_8.9p1 ubuntu-3ubuntu0.1") {
        os_name = "Ubuntu";
        os_version = "22.04";
        os_family = "Linux";
        accuracy = 99;
    }

    // 3. TCP Window Size refinement
    if os_family == "Linux" && window_size == 5840 {
        accuracy += 5;
    } else if os_family == "Windows" && (window_size == 8192 || window_size == 65535) {
        accuracy += 5;
    }

    RustOSInfo {
        os_name: CString::new(os_name).unwrap().into_raw(),
        os_version: CString::new(os_version).unwrap().into_raw(),
        os_family: CString::new(os_family).unwrap().into_raw(),
        accuracy,
        ttl,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_detect_os(host: *const c_char, banner_sample: *const c_char, ttl: i32, window_size: i32) -> *mut RustOSInfo {
    let _c_host = CStr::from_ptr(host).to_str().unwrap_or("");
    let c_banner = CStr::from_ptr(banner_sample).to_str().unwrap_or("");
    
    let info = detect_os_from_tcp_params(ttl, window_size, c_banner);
    Box::into_raw(Box::new(info))
}

#[no_mangle]
pub unsafe extern "C" fn rust_free_os_info(ptr: *mut RustOSInfo) {
    if ptr.is_null() { return; }
    let info = Box::from_raw(ptr);
    let _ = CString::from_raw(info.os_name);
    let _ = CString::from_raw(info.os_version);
    let _ = CString::from_raw(info.os_family);
}
