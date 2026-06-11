use std::process::Command;
use std::str;

#[derive(Debug, Clone)]
pub struct AggressiveApResult {
    pub ssid: String,
    pub bssid: String,
    pub channel: u32,
    pub signal: i32,
    pub encryption: String,
    pub vendor: String,
    pub clients_count: u32,
    pub wps: bool,
}

#[derive(Debug, Clone)]
pub struct TargetedApResult {
    pub ssid: String,
    pub bssid: String,
    pub channel: u32,
    pub signal: i32,
    pub encryption: String,
    pub vendor: String,
    pub clients_count: u32,
    pub wps: bool,
    pub connected_clients: Vec<String>,
}

fn get_interface_state(iface: &str) -> Result<(), String> {
    let output = Command::new("ip")
        .args(["link", "show", iface])
        .output()
        .map_err(|e| format!("Failed to execute ip command: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Interface {} not found or not accessible",
            iface
        ));
    }

    let stdout = str::from_utf8(&output.stdout).unwrap_or("");
    if !stdout.contains("state UP") {
        Err(format!("Interface {} is not up", iface))
    } else {
        Ok(())
    }
}

fn set_monitor_mode(iface: &str) -> Result<(), String> {
    Command::new("ip")
        .args(["link", "set", iface, "down"])
        .output()
        .map_err(|e| format!("Failed to bring interface down: {}", e))?;

    let output = Command::new("iw")
        .args(["dev", iface, "set", "type", "monitor"])
        .output()
        .map_err(|e| format!("Failed to set monitor mode: {}", e))?;

    if !output.status.success() {
        let stderr = str::from_utf8(&output.stderr).unwrap_or("unknown error");
        return Err(format!("Failed to set monitor mode: {}", stderr));
    }

    Command::new("ip")
        .args(["link", "set", iface, "up"])
        .output()
        .map_err(|e| format!("Failed to bring interface up: {}", e))?;

    Ok(())
}

fn set_channel(iface: &str, channel: u32) -> Result<(), String> {
    let output = Command::new("iw")
        .args([
            "dev", iface, "set", "channel", &channel.to_string(),
        ])
        .output()
        .map_err(|e| format!("Failed to set channel: {}", e))?;

    if !output.status.success() {
        let stderr = str::from_utf8(&output.stderr).unwrap_or("unknown error");
        return Err(format!("Failed to set channel {}: {}", channel, stderr));
    }

    Ok(())
}

fn run_airodump(iface: &str, channel: Option<u32>, bssid_filter: Option<&str>) -> Result<String, String> {
    let tmp_file = format!("/tmp/scan_{}", std::process::id());
    let csv_path = format!("{}.csv", tmp_file);

    let mut args = vec![
        iface,
        "--write-interval", "1",
        "--output-format", "csv",
        "-w", &tmp_file,
    ];

    let ch_str;
    if let Some(ch) = channel {
        ch_str = ch.to_string();
        args.insert(1, &ch_str);
        args.insert(1, "--channel");
    }

    if let Some(bssid) = bssid_filter {
        args.push("--bssid");
        args.push(bssid);
    }

    let output = Command::new("airodump-ng")
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to run airodump-ng: {}", e))?;

    if !output.status.success() {
        let stderr = str::from_utf8(&output.stderr).unwrap_or("unknown error");
        if !stderr.contains("No such device") {
            return Err(format!("airodump-ng failed: {}", stderr));
        }
    }

    let csv_content = std::fs::read_to_string(&csv_path)
        .map_err(|e| format!("Failed to read scan results: {}", e))?;

    let _ = std::fs::remove_file(&csv_path);
    let _ = std::fs::remove_file(format!("{}.kismet.csv", tmp_file));
    let _ = std::fs::remove_file(format!("{}.kismet.netxml", tmp_file));

    Ok(csv_content)
}

fn parse_airodump_csv(csv: &str) -> Vec<AggressiveApResult> {
    let mut results = Vec::new();
    let lines: Vec<&str> = csv.lines().collect();

    let mut ap_section_start = None;
    let mut client_section_start = None;

    for (i, line) in lines.iter().enumerate() {
        if line.contains("BSSID") && line.contains("Channel") && line.contains("ESSID") {
            ap_section_start = Some(i + 1);
        }
        if line.contains("Station MAC") || line.contains("STATION") {
            client_section_start = Some(i + 1);
        }
    }

    let mut client_map: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    if let Some(start) = client_section_start {
        for line in lines.iter().skip(start) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
            if parts.len() >= 7 {
                let bssid = parts[5].trim().trim_matches('"').trim().to_uppercase();
                if !bssid.is_empty() && bssid != "(not associated)" {
                    *client_map.entry(bssid).or_insert(0) += 1;
                }
            }
        }
    }

    if let Some(start) = ap_section_start {
        for line in lines.iter().skip(start) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
            if parts.len() < 14 {
                continue;
            }

            let bssid = parts[0].trim().trim_matches('"').trim().to_uppercase();
            if bssid.is_empty() || bssid == "BSSID" {
                continue;
            }

            let channel: u32 = parts[3].trim().trim_matches('"').trim().parse().unwrap_or(0);
            let signal: i32 = parts[8]
                .trim()
                .trim_matches('"')
                .trim()
                .replace(" dBm", "")
                .replace("dBm", "")
                .parse()
                .unwrap_or(-100);

            let privacy = parts[6].trim().trim_matches('"').trim().to_uppercase();
            let encryption = if privacy.contains("WPA3") || privacy.contains("SAE") {
                "WPA3".to_string()
            } else if privacy.contains("WPA2") {
                "WPA2".to_string()
            } else if privacy.contains("WPA") {
                "WPA".to_string()
            } else if privacy.contains("WEP") {
                "WEP".to_string()
            } else {
                "Open".to_string()
            };

            let ssid = parts[13].trim().trim_matches('"').trim().to_string();
            let clients_count = client_map.get(&bssid).copied().unwrap_or(0);

            let wps = line.contains("WPS") || parts.iter().any(|p| {
                p.trim().trim_matches('"').to_uppercase().contains("WPS")
            });

            let vendor = detect_vendor(&bssid);

            results.push(AggressiveApResult {
                ssid,
                bssid,
                channel,
                signal,
                encryption,
                vendor,
                clients_count,
                wps,
            });
        }
    }

    results
}

fn detect_vendor(bssid: &str) -> String {
    let prefix = bssid.replace(':', "").to_uppercase();
    if prefix.len() < 6 {
        return "Unknown".to_string();
    }

    let oui = &prefix[..6];
    match oui {
        "001122" => "Cisco".to_string(),
        "001A2B" => "Avaya".to_string(),
        "00226B" => "Cisco".to_string(),
        "00260B" => "Amazon".to_string(),
        "3C5AB4" => "Google".to_string(),
        "44E9DD" => "TP-Link".to_string(),
        "5CA6E6" => "Ubiquiti".to_string(),
        "60A44C" => "ASUSTek".to_string(),
        "788A20" => "Ubiquiti".to_string(),
        "88DC96" => "EnGenius".to_string(),
        "9C9D5D" => "Ralink".to_string(),
        "AC84C6" => "TP-Link".to_string(),
        "B04E26" => "TP-Link".to_string(),
        "C025E9" => "TP-Link".to_string(),
        "D8F15B" => "Netgear".to_string(),
        "E894F6" => "TP-Link".to_string(),
        "F4F26D" => "TP-Link".to_string(),
        _ => "Unknown".to_string(),
    }
}

pub fn aggressive_scan(iface: &str) -> Vec<AggressiveApResult> {
    if let Err(e) = get_interface_state(iface) {
        eprintln!("Interface error: {}", e);
        return Vec::new();
    }

    if let Err(e) = set_monitor_mode(iface) {
        eprintln!("Monitor mode error: {}", e);
    }

    let channels_2g: Vec<u32> = (1..=13).collect();
    let channels_5g: Vec<u32> = vec![36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165];

    let mut all_results: Vec<AggressiveApResult> = Vec::new();
    let mut seen_bssids: std::collections::HashSet<String> = std::collections::HashSet::new();

    for channel in channels_2g.iter().chain(channels_5g.iter()) {
        if set_channel(iface, *channel).is_err() {
            continue;
        }

        match run_airodump(iface, Some(*channel), None) {
            Ok(csv) => {
                let aps = parse_airodump_csv(&csv);
                for ap in aps {
                    if !seen_bssids.contains(&ap.bssid) {
                        seen_bssids.insert(ap.bssid.clone());
                        all_results.push(ap);
                    }
                }
            }
            Err(e) => {
                eprintln!("Scan error on channel {}: {}", channel, e);
            }
        }
    }

    all_results.sort_by(|a, b| b.signal.cmp(&a.signal));
    all_results
}

pub fn targeted_scan(iface: &str, target_bssid: &str) -> Option<TargetedApResult> {
    if let Err(e) = get_interface_state(iface) {
        eprintln!("Interface error: {}", e);
        return None;
    }

    if let Err(e) = set_monitor_mode(iface) {
        eprintln!("Monitor mode error: {}", e);
    }

    let target_upper = target_bssid.to_uppercase();

    for channel in 1..=165u32 {
        if set_channel(iface, channel).is_err() {
            continue;
        }

        if let Ok(csv) = run_airodump(iface, Some(channel), Some(&target_upper)) {
            let aps = parse_airodump_csv(&csv);
            if let Some(ap) = aps.into_iter().find(|a| a.bssid == target_upper) {
                let connected_clients = get_connected_clients(iface, &target_upper);
                return Some(TargetedApResult {
                    ssid: ap.ssid,
                    bssid: ap.bssid,
                    channel: ap.channel,
                    signal: ap.signal,
                    encryption: ap.encryption,
                    vendor: ap.vendor,
                    clients_count: ap.clients_count,
                    wps: ap.wps,
                    connected_clients,
                });
            }
        }
    }

    None
}

fn get_connected_clients(iface: &str, target_bssid: &str) -> Vec<String> {
    let mut clients = Vec::new();

    if let Ok(csv) = run_airodump(iface, None, Some(target_bssid)) {
        let lines: Vec<&str> = csv.lines().collect();
        let mut client_section = false;

        for line in lines {
            let line = line.trim();
            if line.contains("Station MAC") || line.contains("STATION") {
                client_section = true;
                continue;
            }
            if client_section && !line.is_empty() {
                let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 7 {
                    let bssid = parts[5].trim().trim_matches('"').trim().to_uppercase();
                    let mac = parts[0].trim().trim_matches('"').trim().to_uppercase();
                    if bssid == target_bssid && !mac.is_empty() && mac.contains(':') {
                        clients.push(mac);
                    }
                }
            }
        }
    }

    clients
}

pub fn probe_request_flood(iface: &str, ssid: &str, count: u32) -> Result<(), String> {
    if let Err(e) = get_interface_state(iface) {
        return Err(format!("Interface error: {}", e));
    }

    if let Err(e) = set_monitor_mode(iface) {
        return Err(format!("Monitor mode error: {}", e));
    }

    let count_str = count.to_string();

    let mut args: Vec<&str> = vec![
        "--dest", "FF:FF:FF:FF:FF:FF",
        "-e", ssid,
        "-c", "6",
        "--count", &count_str,
        iface,
    ];

    if ssid.is_empty() {
        args = vec![
            "--dest", "FF:FF:FF:FF:FF:FF",
            "-c", "6",
            "--count", &count_str,
            "--probes",
            iface,
        ];
    }

    let output = Command::new("mdk4")
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to run mdk4: {}", e))?;

    if !output.status.success() {
        let stderr = str::from_utf8(&output.stderr).unwrap_or("unknown error");
        return Err(format!("mdk4 probe flood failed: {}", stderr));
    }

    Ok(())
}

pub fn client_hunt(iface: &str, bssid: &str) -> Vec<String> {
    let mut clients = Vec::new();

    if let Err(e) = get_interface_state(iface) {
        eprintln!("Interface error: {}", e);
        return clients;
    }

    if let Err(e) = set_monitor_mode(iface) {
        eprintln!("Monitor mode error: {}", e);
    }

    let target_upper = bssid.to_uppercase();

    let channels_2g: Vec<u32> = (1..=13).collect();
    let channels_5g: Vec<u32> = vec![36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165];

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for channel in channels_2g.iter().chain(channels_5g.iter()) {
        if set_channel(iface, *channel).is_err() {
            continue;
        }

        let found = get_connected_clients(iface, &target_upper);
        for mac in found {
            if !seen.contains(&mac) {
                seen.insert(mac.clone());
                clients.push(mac);
            }
        }
    }

    clients
}
