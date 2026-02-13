use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use serde::{Serialize, Deserialize};
use reqwest::Client;
use tokio::runtime::Runtime;
use futures::future::join_all;
use std::time::Duration;

#[derive(Serialize, Deserialize, Debug)]
pub struct TurboConfig {
    pub target: String,
    pub paths: Vec<String>,
    pub threads: usize,
    pub timeout_ms: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TurboResult {
    pub path: String,
    pub status: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TurboOutput {
    pub results: Vec<TurboResult>,
}

#[no_mangle]
pub extern "C" fn rust_turbo_scan(c_config_json: *const c_char) -> *mut c_char {
    let config_json = unsafe { CStr::from_ptr(c_config_json).to_string_lossy().into_owned() };
    let config: TurboConfig = match serde_json::from_str(&config_json) {
        Ok(c) => c,
        Err(_) => return CString::new("{}").unwrap().into_raw(),
    };

    let rt = Runtime::new().unwrap();
    let output = rt.block_on(async {
        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        let mut results = Vec::new();
        let base_url = config.target.trim_end_matches('/').to_string();

        for chunk in config.paths.chunks(config.threads) {
            let mut tasks = Vec::new();
            for path in chunk {
                let full_url = format!("{}/{}", base_url, path.trim_start_matches('/'));
                let cl = client.clone();
                let p = path.clone();
                tasks.push(tokio::spawn(async move {
                    if let Ok(resp) = cl.get(&full_url).send().await {
                        let status = resp.status().as_u16();
                        if status != 404 {
                            return Some(TurboResult { path: p, status });
                        }
                    }
                    None
                }));
            }

            let chunk_results = join_all(tasks).await;
            for res in chunk_results {
                if let Ok(Some(r)) = res {
                    results.push(r);
                }
            }
        }
        TurboOutput { results }
    });

    let json = serde_json::to_string(&output).unwrap();
    CString::new(json).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn free_turbo_string(s: *mut c_char) {
    if s.is_null() { return; }
    unsafe {
        let _ = CString::from_raw(s);
    }
}
