#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::os::raw::{c_char, c_int, c_long, c_uchar, c_void};

pub type pcap_t = std::ffi::c_void;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pcap_pkthdr {
    pub ts_sec: c_long,
    pub ts_usec: c_long,
    pub caplen: u32,
    pub len: u32,
}

pub type packet_handler_cb = Option<
    unsafe extern "C" fn(
        user: *mut c_uchar,
        pkthdr: *const pcap_pkthdr,
        packet: *const c_uchar,
    ),
>;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pcap_session_t {
    pub handle: *mut pcap_t,
    pub errbuf: [c_char; 256usize],
    pub callback: packet_handler_cb,
}

#[cfg(feature = "c-ffi")]
#[link(name = "hackit_wireless_c", kind = "static")]
extern "C" {
    pub fn hackit_pcap_open(interface_name: *const c_char, monitor_mode: bool) -> *mut pcap_session_t;
    pub fn hackit_pcap_start(session: *mut pcap_session_t, callback: packet_handler_cb) -> c_int;
    pub fn hackit_pcap_stop(session: *mut pcap_session_t);
    pub fn hackit_pcap_close(session: *mut pcap_session_t);
    pub fn hackit_pcap_get_error(session: *mut pcap_session_t) -> *const c_char;
    pub fn hackit_wifi_init() -> bool;
    pub fn hackit_wifi_set_monitor_mode(interface_name: *const c_char) -> bool;
    pub fn hackit_wifi_set_managed_mode(interface_name: *const c_char) -> bool;
    pub fn hackit_wifi_set_channel(interface_name: *const c_char, channel: c_int) -> bool;
    pub fn hackit_wifi_audit_ap(ssid: *const c_char, bssid: *const c_char) -> bool;
    pub fn hackit_wifi_load_whitelist(filepath: *const c_char) -> bool;
    pub fn hackit_wifi_is_ap_whitelisted(ssid: *const c_char, bssid: *const c_char) -> c_int;
    pub fn hackit_wifi_close();
    pub fn hackit_c_detect_adapters(out_adapters: *mut c_void, max_adapters: c_int) -> c_int;
    pub fn hackit_wifi_change_mac(interface_name: *const c_char, new_mac: *const c_char) -> bool;
    pub fn hackit_wifi_restore_mac(interface_name: *const c_char) -> bool;
    pub fn hackit_wifi_set_txpower(interface_name: *const c_char, value: c_int) -> bool;
    pub fn hackit_wifi_get_adapter_info(interface_name: *const c_char, info_buf: *mut c_char, buf_size: c_int) -> bool;
    pub fn hackit_wifi_get_status(interface_name: *const c_char, status_buf: *mut c_char, buf_size: c_int) -> bool;
    pub fn hackit_wifi_channel_to_freq(channel: c_int) -> c_int;
    pub fn hackit_wifi_get_current_channel(interface_name: *const c_char) -> c_int;
    pub fn hackit_c_get_supported_channels(iface_name: *const c_char, out_channels: *mut c_void, max_channels: c_int) -> c_int;
    pub fn hackit_c_set_channel(iface_name: *const c_char, channel: c_int) -> bool;
    pub fn hackit_c_set_monitor_mode(iface_name: *const c_char) -> bool;
    pub fn hackit_c_set_managed_mode(iface_name: *const c_char) -> bool;
    pub fn hackit_c_get_current_channel(iface_name: *const c_char) -> c_int;
}

#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_pcap_open(_interface_name: *const c_char, _monitor_mode: bool) -> *mut pcap_session_t { std::ptr::null_mut() }
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_pcap_start(_session: *mut pcap_session_t, _callback: packet_handler_cb) -> c_int { -1 }
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_pcap_stop(_session: *mut pcap_session_t) {}
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_pcap_close(_session: *mut pcap_session_t) {}
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_pcap_get_error(_session: *mut pcap_session_t) -> *const c_char { std::ptr::null() }
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_wifi_init() -> bool { false }
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_wifi_set_monitor_mode(_: *const c_char) -> bool { false }
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_wifi_set_managed_mode(_: *const c_char) -> bool { false }
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_wifi_set_channel(_: *const c_char, _: c_int) -> bool { false }
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_wifi_audit_ap(_: *const c_char, _: *const c_char) -> bool { false }
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_wifi_load_whitelist(_: *const c_char) -> bool { false }
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_wifi_is_ap_whitelisted(_: *const c_char, _: *const c_char) -> c_int { -1 }
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_wifi_close() {}
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_c_detect_adapters(_: *mut c_void, _: c_int) -> c_int { 0 }
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_wifi_change_mac(_: *const c_char, _: *const c_char) -> bool { false }
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_wifi_restore_mac(_: *const c_char) -> bool { false }
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_wifi_set_txpower(_: *const c_char, _: c_int) -> bool { false }
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_wifi_get_adapter_info(_: *const c_char, _: *mut c_char, _: c_int) -> bool { false }
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_wifi_get_status(_: *const c_char, _: *mut c_char, _: c_int) -> bool { false }
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_wifi_channel_to_freq(_: c_int) -> c_int { -1 }
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_wifi_get_current_channel(_: *const c_char) -> c_int { -1 }
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_c_get_supported_channels(_: *const c_char, _: *mut c_void, _: c_int) -> c_int { 0 }
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_c_set_channel(_: *const c_char, _: c_int) -> bool { false }
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_c_set_monitor_mode(_: *const c_char) -> bool { false }
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_c_set_managed_mode(_: *const c_char) -> bool { false }
#[cfg(not(feature = "c-ffi"))]
pub unsafe fn hackit_c_get_current_channel(_: *const c_char) -> c_int { -1 }
