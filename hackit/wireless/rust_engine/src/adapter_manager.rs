use std::os::raw::{c_char, c_int};
use crate::c_bindings;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CWifiAdapter {
    pub name: [c_char; 32],
    pub mac: [c_char; 18],
    pub driver: [c_char; 32],
    pub channel: c_int,
    pub signal_dbm: c_int,
    pub is_monitor: bool,
}

pub struct RustWifiAdapter {
    pub name: String,
    pub mac: String,
    pub driver: String,
    pub channel: i32,
    pub signal_dbm: i32,
    pub is_monitor: bool,
}

pub fn list_adapters_json() -> String {
    let mut c_adapters = [CWifiAdapter {
        name: [0; 32],
        mac: [0; 18],
        driver: [0; 32],
        channel: 0,
        signal_dbm: 0,
        is_monitor: false,
    }; 10];

    let count = unsafe {
        c_bindings::hackit_c_detect_adapters(
            c_adapters.as_mut_ptr() as *mut std::ffi::c_void,
            10,
        )
    };

    let mut json = String::from("[");
    for i in 0..(count as usize) {
        let adapter = &c_adapters[i];
        
        let name = unsafe { std::ffi::CStr::from_ptr(adapter.name.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        let mac = unsafe { std::ffi::CStr::from_ptr(adapter.mac.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        let driver = unsafe { std::ffi::CStr::from_ptr(adapter.driver.as_ptr()) }
            .to_string_lossy()
            .into_owned();

        if i > 0 {
            json.push_str(", ");
        }

        json.push_str(&format!(
            r#"{{"name": "{}", "mac": "{}", "driver": "{}", "channel": {}, "signal_dbm": {}, "is_monitor": {}}}"#,
            name, mac, driver, adapter.channel, adapter.signal_dbm, adapter.is_monitor
        ));
    }
    json.push(']');
    json
}
