use std::collections::HashMap;

pub fn detect_os(headers: &HashMap<String, String>, body: &str) -> String {
    // Heuristic 1: Server Header
    if let Some(server) = headers.get("Server") {
        let s = server.to_lowercase();
        if s.contains("win32") || s.contains("iis") || s.contains("microsoft") {
            return "Windows Server (IIS)".to_string();
        }
        if s.contains("ubuntu") || s.contains("debian") || s.contains("centos") {
            return format!("Linux ({})", server);
        }
    }

    // Heuristic 2: X-Powered-By
    if let Some(powered) = headers.get("X-Powered-By") {
        if powered.contains("ASP.NET") {
            return "Windows Server".to_string();
        }
    }

    // Heuristic 3: File path casing / style in body
    if body.contains("C:\\") || body.contains("Program Files") {
        return "Windows (Leaked Path)".to_string();
    }
    if body.contains("/var/www") || body.contains("/etc/") {
        return "Linux (Leaked Path)".to_string();
    }

    "Unknown (Likely Linux/Unix)".to_string()
}
