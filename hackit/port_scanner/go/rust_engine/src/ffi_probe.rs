use crate::probe_loader::load_probes_from_path;
use crate::probe_runner::run_probes_for_port;
use crate::probe_engine::LoadedProbes;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use std::ptr;
use std::time::Duration;

pub struct ProbesHandle {
    pub probes: LoadedProbes,
}

#[no_mangle]
pub unsafe extern "C" fn rust_load_probes_dir(path: *const c_char) -> *mut ProbesHandle {
    if path.is_null() {
        return ptr::null_mut();
    }

    let p = match CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let loaded = match load_probes_from_path(Path::new(p)) {
        Ok(v) => v,
        Err(_) => return ptr::null_mut(),
    };

    Box::into_raw(Box::new(ProbesHandle { probes: loaded }))
}

#[no_mangle]
pub unsafe extern "C" fn rust_free_probes_handle(handle: *mut ProbesHandle) {
    if handle.is_null() {
        return;
    }
    let _ = Box::from_raw(handle);
}

#[no_mangle]
pub unsafe extern "C" fn rust_probe_port_json(
    host: *const c_char,
    port: u16,
    handle: *const ProbesHandle,
    timeout_ms: u64,
) -> *mut c_char {
    if host.is_null() || handle.is_null() {
        return CString::new("{}").unwrap().into_raw();
    }

    let host_s = CStr::from_ptr(host).to_str().unwrap_or("");
    let h = &(*handle);

    let report = crate::RUNTIME.block_on(async {
        run_probes_for_port(host_s, port, &h.probes, Duration::from_millis(timeout_ms)).await
    });

    let json = serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string());
    CString::new(json).unwrap().into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn rust_probe_ports_json(
    host: *const c_char,
    ports_ptr: *const u16,
    ports_count: usize,
    handle: *const ProbesHandle,
    timeout_ms: u64,
) -> *mut c_char {
    if host.is_null() || ports_ptr.is_null() || handle.is_null() {
        return CString::new("[]").unwrap().into_raw();
    }

    let host_s = CStr::from_ptr(host).to_str().unwrap_or("");
    let ports = std::slice::from_raw_parts(ports_ptr, ports_count);
    let h = &(*handle);

    let reports = crate::RUNTIME.block_on(async {
        let mut out = Vec::with_capacity(ports.len());
        for &p in ports.iter() {
            out.push(run_probes_for_port(host_s, p, &h.probes, Duration::from_millis(timeout_ms)).await);
        }
        out
    });

    let json = serde_json::to_string(&reports).unwrap_or_else(|_| "[]".to_string());
    CString::new(json).unwrap().into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn rust_free_cstring(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    let _ = CString::from_raw(s);
}
