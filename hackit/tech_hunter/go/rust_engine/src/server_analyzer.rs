use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ServerDetails {
    pub server_name: String,
    pub hosting_provider: String,
    pub cloud_platform: String,
    pub os_info: String,
    pub ip_org: String,
    pub data_center: String,
    pub reverse_proxy: String,
}

pub fn analyze_server(headers: &HashMap<String, String>, _body: &str, _host: &str) -> ServerDetails {
    let mut details = ServerDetails::default();
    
    // 1. Detect Server from Headers
    if let Some(server) = headers.get("server") {
        details.server_name = server.clone();
    }
    
    // 2. Detect OS from Headers
    if let Some(powered_by) = headers.get("x-powered-by") {
        if powered_by.contains("Ubuntu") { details.os_info = "Ubuntu".to_string(); }
        else if powered_by.contains("Debian") { details.os_info = "Debian".to_string(); }
        else if powered_by.contains("CentOS") { details.os_info = "CentOS".to_string(); }
        else if powered_by.contains("Win64") || powered_by.contains("Win32") { details.os_info = "Windows".to_string(); }
    }
    
    if details.os_info.is_empty() {
        if let Some(server) = &headers.get("server") {
            if server.contains("(Ubuntu)") { details.os_info = "Ubuntu".to_string(); }
            else if server.contains("(Debian)") { details.os_info = "Debian".to_string(); }
            else if server.contains("(CentOS)") { details.os_info = "CentOS".to_string(); }
            else if server.contains("Win64") || server.contains("IIS") { details.os_info = "Windows".to_string(); }
            else if server.contains("Unix") { details.os_info = "Unix-like".to_string(); }
        }
    }

    // 3. Detect Hosting & Cloud
    
    // Header based signals
    if headers.contains_key("x-amz-request-id") || headers.contains_key("x-amz-id-2") {
        details.hosting_provider = "Amazon Web Services (AWS)".to_string();
        details.cloud_platform = "AWS".to_string();
    } else if headers.contains_key("cf-ray") || headers.get("server").map_or(false, |s| s.contains("cloudflare")) {
        details.hosting_provider = "Cloudflare".to_string();
        details.reverse_proxy = "Cloudflare CDN".to_string();
    } else if headers.contains_key("x-goog-generation") || headers.contains_key("x-guploader-uploadid") {
        details.hosting_provider = "Google Cloud Platform (GCP)".to_string();
        details.cloud_platform = "GCP".to_string();
    } else if headers.contains_key("x-azure-ref") || headers.contains_key("x-ms-request-id") {
        details.hosting_provider = "Microsoft Azure".to_string();
        details.cloud_platform = "Azure".to_string();
    } else if headers.get("server").map_or(false, |s| s.contains("gws")) {
        details.hosting_provider = "Google".to_string();
    } else if headers.contains_key("x-akamai-transformed") {
        details.hosting_provider = "Akamai".to_string();
    } else if headers.contains_key("x-fastly-request-id") {
        details.hosting_provider = "Fastly".to_string();
    } else if headers.get("server").map_or(false, |s| s.contains("ArvanCloud")) {
        details.hosting_provider = "ArvanCloud".to_string();
    }

    // 4. Reverse Proxy Detection
    if headers.contains_key("x-nginx-proxy") || headers.get("server").map_or(false, |s| s.contains("nginx")) {
        details.reverse_proxy = "Nginx".to_string();
    } else if headers.contains_key("via") {
        details.reverse_proxy = headers.get("via").unwrap().clone();
    } else if headers.contains_key("x-varnish") {
        details.reverse_proxy = "Varnish Cache".to_string();
    }

    details
}
