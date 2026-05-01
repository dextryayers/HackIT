// Ultra-Fast Rust Port Scanner with Nmap-like Capabilities
// Masscan-style performance with real-time streaming

use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};
use std::thread;
use std::collections::HashMap;
use std::sync::mpsc::{channel, Sender, Receiver};

// Port states
#[derive(Clone, Debug, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
}

// Port scan result
#[derive(Clone, Debug)]
pub struct PortResult {
    pub port: u16,
    pub state: PortState,
    pub service: String,
    pub banner: String,
    pub version: String,
    pub latency_ms: u64,
}

// Scan configuration
#[derive(Clone)]
pub struct ScanConfig {
    pub timeout_ms: u64,
    pub threads: usize,
    pub stealth: bool,
    pub scan_type: ScanType,
    pub rate_limit: Option<u64>, // packets per second
}

#[derive(Clone, Copy, PartialEq)]
pub enum ScanType {
    Connect,
    Syn,
    Fin,
    Null,
    Xmas,
    Udp,
}

// Ultra-fast mass scanner
pub struct MassScanner {
    config: ScanConfig,
    results: Arc<Mutex<Vec<PortResult>>>,
}

impl MassScanner {
    pub fn new(config: ScanConfig) -> Self {
        MassScanner {
            config,
            results: Arc::new(Mutex::new(Vec::new())),
        }
    }

    // Mass scan like masscan - ultra fast
    pub fn mass_scan(&self, target: &str, ports: &[u16]) -> Vec<PortResult> {
        let start = Instant::now();
        let target_addr: std::net::Ipv4Addr = target.parse().unwrap_or(std::net::Ipv4Addr::new(127, 0, 0, 1));
        
        // Use rayon for parallel processing
        let port_results: Vec<PortResult> = ports.par_iter()
            .map(|&port| self.scan_port(target_addr, port))
            .filter(|result| result.state == PortState::Open || result.state == PortState::OpenFiltered)
            .collect();

        let elapsed = start.elapsed();
        println!("Scanned {} ports in {:?}", ports.len(), elapsed);
        
        port_results
    }

    // Real-time streaming scan
    pub fn streaming_scan<F>(&self, target: &str, ports: &[u16], callback: F) 
    where 
        F: Fn(PortResult) + Send + Sync + 'static
    {
        let target_addr: std::net::Ipv4Addr = target.parse().unwrap_or(std::net::Ipv4Addr::new(127, 0, 0, 1));
        let config = self.config.clone();
        let callback = Arc::new(callback);

        // Use thread pool for concurrent scanning
        let (tx, rx): (Sender<PortResult>, Receiver<PortResult>) = channel();
        
        // Spawn worker threads
        let num_threads = config.threads.min(ports.len());
        let ports_per_thread = ports.len() / num_threads;
        
        for thread_id in 0..num_threads {
            let tx = tx.clone();
            let ports_chunk = ports[thread_id * ports_per_thread..].to_vec();
            let target = target_addr;
            let cfg = config.clone();
            
            thread::spawn(move || {
                for &port in ports_chunk {
                    let result = Self::scan_port_thread(target, port, &cfg);
                    let _ = tx.send(result);
                }
            });
        }

        // Process results in real-time
        drop(tx); // Drop sender to close channel when all threads finish
        
        for result in rx {
            if result.state == PortState::Open || result.state == PortState::OpenFiltered {
                callback(result);
            }
        }
    }

    // Adaptive scan with timing adjustment
    pub fn adaptive_scan(&self, target: &str, ports: &[u16]) -> Vec<PortResult> {
        let mut results = Vec::new();
        let target_addr: std::net::Ipv4Addr = target.parse().unwrap_or(std::net::Ipv4Addr::new(127, 0, 0, 1));
        
        // Implement adaptive timing based on network response
        let mut current_timeout = self.config.timeout_ms;
        
        for &port in ports {
            let start = Instant::now();
            let result = self.scan_port(target_addr, port);
            let elapsed = start.elapsed();

            // Adaptive timeout adjustment
            if result.state == PortState::Open {
                if elapsed.as_millis() < current_timeout as u128 / 2 {
                    current_timeout = (current_timeout * 9) / 10;
                }
            } else {
                if elapsed.as_millis() >= current_timeout as u128 {
                    current_timeout = (current_timeout * 11) / 10;
                }
            }

            if result.state == PortState::Open {
                results.push(result);
            }
        }

        results
    }

    // Priority scan (common ports first)
    pub fn priority_scan(&self, target: &str, ports: &[u16]) -> Vec<PortResult> {
        let common_ports = vec![21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432];
        let other_ports: Vec<u16> = ports.iter()
            .filter(|&&p| !common_ports.contains(&p))
            .cloned()
            .collect();

        let mut results = Vec::new();
        
        // Scan common ports first
        results.extend(self.mass_scan(target, &common_ports));
        
        // Then scan remaining ports
        results.extend(self.mass_scan(target, &other_ports));

        results
    }

    // Internal scan methods
    fn scan_port(&self, target: std::net::Ipv4Addr, port: u16) -> PortResult {
        let start = Instant::now();
        
        let state = match self.config.scan_type {
            ScanType::Connect => self.connect_scan(target, port),
            ScanType::Syn => self.syn_scan_port(target, port).state,
            ScanType::Fin => self.fin_scan(target, port).state,
            ScanType::Null => self.null_scan(target, port).state,
            ScanType::Xmas => self.xmas_scan(target, port).state,
            ScanType::Udp => self.udp_scan_port(target, port).state,
        };

        let latency = start.elapsed().as_millis() as u64;

        PortResult {
            port,
            state,
            service: self.identify_service(port),
            banner: String::new(),
            version: String::new(),
            latency_ms: latency,
        }
    }

    fn scan_port_thread(target: std::net::Ipv4Addr, port: u16, config: &ScanConfig) -> PortResult {
        let start = Instant::now();
        
        let state = match config.scan_type {
            ScanType::Connect => Self::connect_scan_thread(target, port, config),
            ScanType::Syn => Self::syn_scan_port_thread(target, port, config).state,
            _ => PortState::Filtered,
        };

        let latency = start.elapsed().as_millis() as u64;

        PortResult {
            port,
            state,
            service: Self::identify_service_thread(port),
            banner: String::new(),
            version: String::new(),
            latency_ms: latency,
        }
    }

    // Connect scan (standard TCP handshake)
    fn connect_scan(&self, target: std::net::Ipv4Addr, port: u16) -> PortState {
        let addr = SocketAddr::new(std::net::IpAddr::V4(target), port);
        let timeout = Duration::from_millis(self.config.timeout_ms);

        match TcpStream::connect_timeout(addr, timeout) {
            Ok(_) => PortState::Open,
            Err(_) => PortState::Closed,
        }
    }

    fn connect_scan_thread(target: std::net::Ipv4Addr, port: u16, config: &ScanConfig) -> PortState {
        let addr = SocketAddr::new(std::net::IpAddr::V4(target), port);
        let timeout = Duration::from_millis(config.timeout_ms);

        match TcpStream::connect_timeout(addr, timeout) {
            Ok(_) => PortState::Open,
            Err(_) => PortState::Closed,
        }
    }

    // SYN scan implementation
    fn syn_scan_port(&self, target: std::net::Ipv4Addr, port: u16) -> PortResult {
        // SYN scan requires raw sockets (root/admin privileges)
        // This is a placeholder for the actual implementation
        PortResult {
            port,
            state: PortState::Filtered,
            service: String::new(),
            banner: String::new(),
            version: String::new(),
            latency_ms: 0,
        }
    }

    fn syn_scan_port_thread(target: std::net::Ipv4Addr, port: u16, config: &ScanConfig) -> PortResult {
        // SYN scan requires raw sockets
        PortResult {
            port,
            state: PortState::Filtered,
            service: String::new(),
            banner: String::new(),
            version: String::new(),
            latency_ms: 0,
        }
    }

    // FIN scan
    fn fin_scan(&self, target: std::net::Ipv4Addr, port: u16) -> PortResult {
        // FIN scan requires raw sockets
        PortResult {
            port,
            state: PortState::Filtered,
            service: String::new(),
            banner: String::new(),
            version: String::new(),
            latency_ms: 0,
        }
    }

    // NULL scan
    fn null_scan(&self, target: std::net::Ipv4Addr, port: u16) -> PortResult {
        // NULL scan requires raw sockets
        PortResult {
            port,
            state: PortState::Filtered,
            service: String::new(),
            banner: String::new(),
            version: String::new(),
            latency_ms: 0,
        }
    }

    // Xmas scan
    fn xmas_scan(&self, target: std::net::Ipv4Addr, port: u16) -> PortResult {
        // Xmas scan requires raw sockets
        PortResult {
            port,
            state: PortState::Filtered,
            service: String::new(),
            banner: String::new(),
            version: String::new(),
            latency_ms: 0,
        }
    }

    // UDP scan
    fn udp_scan_port(&self, target: std::net::Ipv4Addr, port: u16) -> PortResult {
        let addr = SocketAddr::new(std::net::IpAddr::V4(target), port);
        let timeout = Duration::from_millis(self.config.timeout_ms);

        match UdpSocket::bind(addr) {
            Ok(_) => PortResult {
                port,
                state: PortState::Open,
                service: "udp".to_string(),
                banner: String::new(),
                version: String::new(),
                latency_ms: 0,
            },
            Err(_) => PortResult {
                port,
                state: PortState::Filtered,
                service: String::new(),
                banner: String::new(),
                version: String::new(),
                latency_ms: 0,
            },
        }
    }

    // Service identification
    fn identify_service(port: u16) -> String {
        let common_ports: HashMap<u16, &str> = [
            (21, "ftp"),
            (22, "ssh"),
            (23, "telnet"),
            (25, "smtp"),
            (53, "dns"),
            (80, "http"),
            (110, "pop3"),
            (111, "rpcbind"),
            (113, "ident"),
            (119, "nntp"),
            (123, "ntp"),
            (135, "msrpc"),
            (137, "netbios-ns"),
            (138, "netbios-dgm"),
            (139, "netbios-ssn"),
            (143, "imap"),
            (161, "snmp"),
            (162, "snmptrap"),
            (179, "bgp"),
            (194, "irc"),
            (389, "ldap"),
            (443, "https"),
            (445, "microsoft-ds"),
            (464, "kpasswd"),
            (465, "smtps"),
            (513, "rlogin"),
            (514, "syslog"),
            (515, "printer"),
            (543, "klogin"),
            (544, "kshell"),
            (548, "afp"),
            (554, "rtsp"),
            (587, "submission"),
            (631, "ipp"),
            (636, "ldaps"),
            (873, "rsync"),
            (990, "ftps"),
            (993, "imaps"),
            (995, "pop3s"),
            (1025, "msrpc"),
            (1080, "socks"),
            (1194, "openvpn"),
            (1433, "mssql"),
            (1434, "ms-sql-m"),
            (1521, "oracle"),
            (1723, "pptp"),
            (1883, "mqtt"),
            (2049, "nfs"),
            (2121, "ftp-alt"),
            (2375, "docker"),
            (2376, "docker-ssl"),
            (3306, "mysql"),
            (3389, "ms-wbt-server"),
            (3690, "svn"),
            (4444, "metasploit"),
            (5000, "upnp"),
            (5432, "postgresql"),
            (5672, "amqp"),
            (5900, "vnc"),
            (5984, "couchdb"),
            (6379, "redis"),
            (6443, "kubernetes-api"),
            (6667, "irc"),
            (7000, "cassandra"),
            (7001, "cassandra"),
            (8000, "http-alt"),
            (8080, "http-proxy"),
            (8081, "http-alt"),
            (8443, "https-alt"),
            (8888, "http-alt"),
            (9000, "php-fpm"),
            (9042, "cassandra-native"),
            (9090, "zeus-admin"),
            (9092, "kafka"),
            (9100, "jetdirect"),
            (9200, "elasticsearch"),
            (9418, "git"),
            (9999, "adb"),
            (10000, "webmin"),
            (11211, "memcached"),
            (22222, "ssh-alt"),
            (26257, "cockroachdb"),
            (27017, "mongodb"),
            (27018, "mongodb"),
            (28017, "mongodb-web"),
            (50000, "db2"),
            (54321, "database-alt"),
        ].iter().cloned().collect();

        common_ports.get(&port).unwrap_or(&"unknown").to_string()
    }

    fn identify_service_thread(port: u16) -> String {
        let common_ports: HashMap<u16, &str> = [
            (21, "ftp"),
            (22, "ssh"),
            (23, "telnet"),
            (25, "smtp"),
            (53, "dns"),
            (80, "http"),
            (110, "pop3"),
            (111, "rpcbind"),
            (113, "ident"),
            (119, "nntp"),
            (123, "ntp"),
            (135, "msrpc"),
            (137, "netbios-ns"),
            (138, "netbios-dgm"),
            (139, "netbios-ssn"),
            (143, "imap"),
            (161, "snmp"),
            (162, "snmptrap"),
            (179, "bgp"),
            (194, "irc"),
            (389, "ldap"),
            (443, "https"),
            (445, "microsoft-ds"),
            (464, "kpasswd"),
            (465, "smtps"),
            (513, "rlogin"),
            (514, "syslog"),
            (515, "printer"),
            (543, "klogin"),
            (544, "kshell"),
            (548, "afp"),
            (554, "rtsp"),
            (587, "submission"),
            (631, "ipp"),
            (636, "ldaps"),
            (873, "rsync"),
            (990, "ftps"),
            (993, "imaps"),
            (995, "pop3s"),
            (1025, "msrpc"),
            (1080, "socks"),
            (1194, "openvpn"),
            (1433, "mssql"),
            (1434, "ms-sql-m"),
            (1521, "oracle"),
            (1723, "pptp"),
            (1883, "mqtt"),
            (2049, "nfs"),
            (2121, "ftp-alt"),
            (2375, "docker"),
            (2376, "docker-ssl"),
            (3306, "mysql"),
            (3389, "ms-wbt-server"),
            (3690, "svn"),
            (4444, "metasploit"),
            (5000, "upnp"),
            (5432, "postgresql"),
            (5672, "amqp"),
            (5900, "vnc"),
            (5984, "couchdb"),
            (6379, "redis"),
            (6443, "kubernetes-api"),
            (6667, "irc"),
            (7000, "cassandra"),
            (7001, "cassandra"),
            (8000, "http-alt"),
            (8080, "http-proxy"),
            (8081, "http-alt"),
            (8443, "https-alt"),
            (8888, "http-alt"),
            (9000, "php-fpm"),
            (9042, "cassandra-native"),
            (9090, "zeus-admin"),
            (9092, "kafka"),
            (9100, "jetdirect"),
            (9200, "elasticsearch"),
            (9418, "git"),
            (9999, "adb"),
            (10000, "webmin"),
            (11211, "memcached"),
            (22222, "ssh-alt"),
            (26257, "cockroachdb"),
            (27017, "mongodb"),
            (27018, "mongodb"),
            (28017, "mongodb-web"),
            (50000, "db2"),
            (54321, "database-alt"),
        ].iter().cloned().collect();

        common_ports.get(&port).unwrap_or(&"unknown").to_string()
    }
}

// FFI Interface for Go/C
#[no_mangle]
pub extern "C" fn rust_mass_scan(
    target: *const i8, 
    ports_ptr: *const u16, 
    ports_count: usize, 
    timeout_ms: u64
) -> *const i8 {
    let c_target = std::ffi::CStr::from_ptr(target).to_str().unwrap_or("");
    let ports = unsafe { std::slice::from_raw_parts(ports_ptr, ports_count).to_vec() };
    
    let config = ScanConfig {
        timeout_ms,
        threads: 100,
        stealth: false,
        scan_type: ScanType::Connect,
        rate_limit: None,
    };
    
    let scanner = MassScanner::new(config);
    let results = scanner.mass_scan(c_target, &ports);
    
    // Format results as JSON
    let mut output = String::new();
    output.push('[');
    
    for (i, result) in results.iter().enumerate() {
        if i > 0 { output.push(','); }
        output.push_str(&format!(
            "{{\"port\":{},\"state\":\"{:?}\",\"service\":\"{}\",\"latency\":{}}}",
            result.port, result.state, result.service, result.latency_ms
        ));
    }
    
    output.push(']');
    
    let c_output = std::ffi::CString::new(output).unwrap();
    c_output.into_raw() as *const i8
}

#[no_mangle]
pub extern "C" fn rust_free_string(s: *mut i8) {
    if s.is_null() { return; }
    let _ = std::ffi::CString::from_raw(s);
}
