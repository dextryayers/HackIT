/// Phase 4b: Advanced Port Scanner
/// SYN stealth scan, TCP connect scan, service detection, OS fingerprinting

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::network_recon::{self, ServiceInfo, PortState, ScanResult, parse_port_range, TOP_1000_PORTS, grab_banner, identify_service, detect_service_version};

#[derive(Debug, Clone, PartialEq)]
pub enum ScanType {
    TcpConnect,
    SynStealth,
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub host: String,
    pub ports: Vec<u16>,
    pub scan_type: ScanType,
    pub timeout_ms: u64,
    pub threads: usize,
    pub rate_limit: u32,
    pub randomize: bool,
    pub retries: u32,
    pub grab_banners: bool,
    pub os_detection: bool,
    pub output_json: bool,
}

impl ScanConfig {
    pub fn new(host: &str) -> Self {
        ScanConfig {
            host: host.to_string(),
            ports: Vec::new(),
            scan_type: ScanType::TcpConnect,
            timeout_ms: 3000,
            threads: 64,
            rate_limit: 0,
            randomize: false,
            retries: 1,
            grab_banners: false,
            os_detection: false,
            output_json: false,
        }
    }

    pub fn with_ports(mut self, ports: Vec<u16>) -> Self {
        self.ports = ports;
        self
    }

    pub fn with_port_range(mut self, range: &str) -> Self {
        self.ports = parse_port_range(range);
        self
    }

    pub fn with_top_ports(mut self, n: usize) -> Self {
        let n = n.min(TOP_1000_PORTS.len());
        self.ports = TOP_1000_PORTS[..n].to_vec();
        self
    }

    pub fn with_scan_type(mut self, scan_type: ScanType) -> Self {
        self.scan_type = scan_type;
        self
    }

    pub fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    pub fn with_threads(mut self, t: usize) -> Self {
        self.threads = t.max(1);
        self
    }

    pub fn with_rate(mut self, rate: u32) -> Self {
        self.rate_limit = rate;
        self
    }

    pub fn with_randomize(mut self, r: bool) -> Self {
        self.randomize = r;
        self
    }

    pub fn with_retries(mut self, r: u32) -> Self {
        self.retries = r.max(1);
        self
    }

    pub fn with_banners(mut self, b: bool) -> Self {
        self.grab_banners = b;
        self
    }

    pub fn with_os_detection(mut self, o: bool) -> Self {
        self.os_detection = o;
        self
    }
}

pub fn run_scan(config: ScanConfig) -> ScanResult {
    run_scan_inner(config, None)
}

pub fn run_scan_async<F>(config: ScanConfig, progress: F) -> ScanResult
where
    F: Fn(usize, usize) + Send + 'static,
{
    run_scan_inner(config, Some(Box::new(progress)))
}

fn run_scan_inner(config: ScanConfig, progress: Option<Box<dyn Fn(usize, usize) + Send>>) -> ScanResult {
    let start = Instant::now();
    let host = config.host.clone();
    let ip = resolve_host(&host).unwrap_or_else(|| host.clone());

    let mut ports = if config.ports.is_empty() {
        TOP_1000_PORTS[..100].to_vec()
    } else {
        config.ports.clone()
    };

    if config.randomize {
        ports = shuffle_ports(&ports);
    }

    let total = ports.len();
    let open_ports = Arc::new(Mutex::new(Vec::new()));
    let completed = Arc::new(AtomicU32::new(0));
    let start_time = Arc::new(start);
    let mut rtt_samples: Vec<f64> = Vec::new();

    let mut handles = Vec::new();
    let chunk_size = (total + config.threads - 1) / config.threads;

    for chunk in ports.chunks(chunk_size) {
        let chunk_owned = chunk.to_vec();
        let host_clone = host.clone();
        let open_ports_clone = open_ports.clone();
        let completed_clone = completed.clone();
        let start_time_clone = start_time.clone();
        let timeout = config.timeout_ms;
        let retries = config.retries;
        let grab_banners = config.grab_banners;
        let scan_type = config.scan_type.clone();
        let total_ports = total;

        let progress_cb = if let Some(ref cb) = progress {
            let cb_clone = /* need Arc for closure */ {
                struct Wrap(Box<dyn Fn(usize, usize) + Send>);
                unsafe impl Send for Wrap {}
                let ptr: *const Box<dyn Fn(usize, usize) + Send> = cb as *const Box<dyn Fn(usize, usize) + Send>;
                Some(Wrap(unsafe { (&*ptr).clone_boxed() }))
            };
            Some(progress_cb)
        } else {
            None
        };

        let handle = thread::spawn(move || {
            for &port in &chunk_owned {
                let (is_open, is_filtered) = match scan_type {
                    ScanType::SynStealth => {
                        syn_scan_port(&host_clone, port, timeout)
                    }
                    ScanType::TcpConnect => {
                        tcp_connect_port(&host_clone, port, timeout, retries)
                    }
                };

                if is_open {
                    let mut service_name = identify_service(port);
                    let mut product = None;
                    let mut version = None;
                    let mut banner = None;

                    if grab_banners {
                        if let Some(b) = grab_banner_with_timeout(&host_clone, port, timeout) {
                            banner = Some(b.clone());
                            let (svc, ver) = detect_service_version(&b);
                            service_name = svc;
                            version = ver;
                            product = Some(service_name.clone());
                        }
                    }

                    let elapsed = start_time_clone.elapsed().as_secs_f64() * 1000.0;

                    let svc = ServiceInfo {
                        port,
                        state: PortState::Open,
                        service: service_name,
                        product,
                        version,
                        banner,
                        os_hint: None,
                    };
                    let mut opened = open_ports_clone.lock().unwrap();
                    opened.push(svc);
                }

                let done = completed_clone.fetch_add(1, Ordering::SeqCst) + 1;
                if let Some(ref cb_inner) = progress_cb {
                    (cb_inner.0)(done, total_ports);
                }
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }

    let scan_time_ms = start.elapsed().as_millis() as u64;
    let mut open_ports_vec = open_ports.lock().unwrap().clone();
    open_ports_vec.sort_by_key(|s| s.port);

    let os_guess = if config.os_detection {
        let open_port_nums: Vec<u16> = open_ports_vec.iter().map(|s| s.port).collect();
        detect_os_by_ports(&host, &open_port_nums)
    } else {
        None
    };

    let rtt_min = rtt_samples.iter().cloned().fold(f64::INFINITY, f64::min);
    let rtt_max = rtt_samples.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let rtt_avg = if rtt_samples.is_empty() {
        0.0
    } else {
        rtt_samples.iter().sum::<f64>() / rtt_samples.len() as f64
    };

    ScanResult {
        host: host.clone(),
        ip,
        total_ports_scanned: total,
        open_ports: open_ports_vec,
        scan_time_ms,
        os_guess,
        rtt_min: if rtt_min.is_infinite() { 0.0 } else { rtt_min },
        rtt_max: if rtt_max.is_infinite() { 0.0 } else { rtt_max },
        rtt_avg,
    }
}

trait BoxedClone: Fn(usize, usize) + Send {
    fn clone_boxed(&self) -> Box<dyn Fn(usize, usize) + Send>;
}

impl<T> BoxedClone for T
where
    T: Fn(usize, usize) + Send + Clone + 'static,
{
    fn clone_boxed(&self) -> Box<dyn Fn(usize, usize) + Send> {
        Box::new(self.clone())
    }
}

fn tcp_connect_port(host: &str, port: u16, timeout_ms: u64, retries: u32) -> (bool, bool) {
    for _ in 0..retries {
        let addr_str = format!("{}:{}", host, port);
        let timeout = Duration::from_millis(timeout_ms);
        if let Ok(stream) = TcpStream::connect_timeout(&addr_str.parse::<SocketAddr>().unwrap_or(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
        ), timeout) {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
            let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
            return (true, false);
        }
    }
    (false, true)
}

pub fn syn_scan_port(host: &str, port: u16, timeout_ms: u64) -> (bool, bool) {
    #[cfg(target_os = "linux")]
    {
        match raw_syn_scan(host, port, timeout_ms) {
            Ok(result) => return result,
            Err(_) => {}
        }
    }
    tcp_connect_port(host, port, timeout_ms, 1)
}

#[cfg(target_os = "linux")]
fn raw_syn_scan(host: &str, port: u16, timeout_ms: u64) -> Result<(bool, bool), String> {
    let ip_str = resolve_host(host).ok_or_else(|| "DNS resolution failed".to_string())?;
    let dst_ip: Ipv4Addr = ip_str
        .parse()
        .map_err(|_| "Invalid IP address".to_string())?;

    let src_ip = get_local_ipv4().ok_or_else(|| "Cannot determine local IP".to_string())?;

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP) };
    if sock < 0 {
        return Err("Cannot create raw socket".to_string());
    }

    let enable: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            sock,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        unsafe { libc::close(sock); }
        return Err("Cannot set IP_HDRINCL".to_string());
    }

    let src_port = get_ephemeral_port();
    let seq_num = get_ephemeral_port() as u32 | ((SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() & 0xFFFF) as u32)
        << 16;

    let packet = build_syn_packet(src_ip, dst_ip, src_port, port, seq_num);
    if packet.is_empty() {
        unsafe { libc::close(sock); }
        return Err("Failed to build SYN packet".to_string());
    }

    let dst_addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(dst_ip).to_be(),
        },
        sin_zero: [0i8; 8],
    };

    let sent = unsafe {
        libc::sendto(
            sock,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &dst_addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };

    if sent < 0 {
        unsafe { libc::close(sock); }
        return Err("sendto failed".to_string());
    }

    let recv_sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP) };
    if recv_sock < 0 {
        unsafe { libc::close(sock); }
        return Err("Cannot create receive socket".to_string());
    }

    let tv = libc::timeval {
        tv_sec: (timeout_ms / 1000) as libc::time_t,
        tv_usec: ((timeout_ms % 1000) * 1000) as libc::suseconds_t,
    };
    unsafe {
        libc::setsockopt(
            recv_sock,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    let start = Instant::now();
    let deadline = Duration::from_millis(timeout_ms);
    let dst_ip_u32 = u32::from(dst_ip);

    loop {
        if start.elapsed() > deadline {
            unsafe { libc::close(recv_sock); libc::close(sock); }
            return Ok((false, true));
        }

        let mut buf = [0u8; 65535];
        let mut from_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut from_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        let n = unsafe {
            libc::recvfrom(
                recv_sock,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut from_addr as *mut _ as *mut libc::sockaddr,
                &mut from_len,
            )
        };

        if n < 0 {
            unsafe { libc::close(recv_sock); libc::close(sock); }
            return Ok((false, true));
        }

        let n = n as usize;
        if n < 40 {
            continue;
        }

        let ip_hdr_len = ((buf[0] & 0x0F) as usize) * 4;
        if ip_hdr_len + 20 > n {
            continue;
        }

        let src_ip_from = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        if src_ip_from != dst_ip_u32 {
            continue;
        }

        let tcp_offset = ip_hdr_len;
        let tcphdr_src_port = u16::from_be_bytes([buf[tcp_offset], buf[tcp_offset + 1]]);
        let tcphdr_dst_port = u16::from_be_bytes([buf[tcp_offset + 2], buf[tcp_offset + 3]]);

        if tcphdr_dst_port != src_port {
            continue;
        }

        let flags = buf[tcp_offset + 13];
        let ack = (flags & 0x10) != 0;
        let rst = (flags & 0x04) != 0;
        let syn = (flags & 0x02) != 0;

        if ack && syn {
            unsafe { libc::close(recv_sock); libc::close(sock); }
            return Ok((true, false));
        }
        if rst {
            unsafe { libc::close(recv_sock); libc::close(sock); }
            return Ok((false, false));
        }
    }
}

#[cfg(target_os = "linux")]
fn get_local_ipv4() -> Option<Ipv4Addr> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return None;
    }

    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 80u16.to_be(),
        sin_addr: libc::in_addr {
            s_addr: 0x08080808u32.to_be(),
        },
        sin_zero: [0i8; 8],
    };

    let ret = unsafe {
        libc::connect(
            sock,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };

    if ret < 0 {
        unsafe { libc::close(sock); }
        return None;
    }

    let mut local_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut addr_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockname(
            sock,
            &mut local_addr as *mut _ as *mut libc::sockaddr,
            &mut addr_len,
        )
    };

    unsafe { libc::close(sock); }

    if ret < 0 {
        return None;
    }

    let ip_u32 = u32::from_be(unsafe { local_addr.sin_addr.s_addr });
    Some(Ipv4Addr::from(ip_u32))
}

#[cfg(target_os = "linux")]
fn build_syn_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(40);

    let src_u32 = u32::from(src_ip);
    let dst_u32 = u32::from(dst_ip);

    let ip_ver_ihl: u8 = 0x45;
    let ip_dscp_ecn: u8 = 0;
    let ip_total_len: u16 = 40;
    let ip_id: u16 = (seq_num & 0xFFFF) as u16;
    let ip_flags_fo: u16 = 0;
    let ip_ttl: u8 = 64;
    let ip_proto: u8 = 6;
    let ip_checksum: u16 = 0;

    packet.extend_from_slice(&ip_ver_ihl.to_be_bytes());
    packet.extend_from_slice(&ip_dscp_ecn.to_be_bytes());
    packet.extend_from_slice(&ip_total_len.to_be_bytes());
    packet.extend_from_slice(&ip_id.to_be_bytes());
    packet.extend_from_slice(&ip_flags_fo.to_be_bytes());
    packet.extend_from_slice(&ip_ttl.to_be_bytes());
    packet.extend_from_slice(&ip_proto.to_be_bytes());
    packet.extend_from_slice(&ip_checksum.to_be_bytes());
    packet.extend_from_slice(&src_u32.to_be_bytes());
    packet.extend_from_slice(&dst_u32.to_be_bytes());

    let ip_checksum_val = ipv4_checksum(&packet[..20]);
    packet[10] = (ip_checksum_val >> 8) as u8;
    packet[11] = (ip_checksum_val & 0xFF) as u8;

    let tcp_src = src_port;
    let tcp_dst = dst_port;
    let tcp_seq = seq_num;
    let tcp_ack: u32 = 0;
    let tcp_offset: u8 = 5 << 4;
    let tcp_flags: u8 = 0x02;
    let tcp_window: u16 = 65535;
    let tcp_checksum: u16 = 0;
    let tcp_urgent: u16 = 0;

    packet.push((tcp_src >> 8) as u8);
    packet.push((tcp_src & 0xFF) as u8);
    packet.push((tcp_dst >> 8) as u8);
    packet.push((tcp_dst & 0xFF) as u8);
    packet.extend_from_slice(&tcp_seq.to_be_bytes());
    packet.extend_from_slice(&tcp_ack.to_be_bytes());
    packet.push(tcp_offset);
    packet.push(tcp_flags);
    packet.extend_from_slice(&tcp_window.to_be_bytes());
    packet.extend_from_slice(&tcp_checksum.to_be_bytes());
    packet.extend_from_slice(&tcp_urgent.to_be_bytes());

    let tcp_checksum_val = tcp_checksum_ipv4(&packet[20..40], src_ip, dst_ip);
    let cs_idx = 20 + 16;
    packet[cs_idx] = (tcp_checksum_val >> 8) as u8;
    packet[cs_idx + 1] = (tcp_checksum_val & 0xFF) as u8;

    packet
}

#[cfg(target_os = "linux")]
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(target_os = "linux")]
fn tcp_checksum_ipv4(segment: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> u16 {
    let src_u32 = u32::from(src);
    let dst_u32 = u32::from(dst);

    let pseudo_len = 12 + segment.len();
    let mut buf = Vec::with_capacity(pseudo_len);

    buf.extend_from_slice(&src_u32.to_be_bytes());
    buf.extend_from_slice(&dst_u32.to_be_bytes());
    buf.push(0);
    buf.push(6);
    let seg_len = segment.len() as u16;
    buf.extend_from_slice(&seg_len.to_be_bytes());
    buf.extend_from_slice(segment);

    if buf.len() % 2 != 0 {
        buf.push(0);
    }

    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < buf.len() {
        sum += u16::from_be_bytes([buf[i], buf[i + 1]]) as u32;
        i += 2;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn get_ephemeral_port() -> u16 {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros();
    ((t % 64511) + 1024) as u16
}

pub fn syn_scan_ports(
    host: &str,
    ports: &[u16],
    timeout_ms: u64,
    threads: usize,
    rate_limit: u32,
) -> Vec<(u16, bool)> {
    let results = Arc::new(Mutex::new(Vec::new()));
    let completed = Arc::new(AtomicU32::new(0));
    let total = ports.len();
    let mut handles = Vec::new();
    let chunk_size = (total + threads - 1) / threads;

    for chunk in ports.chunks(chunk_size) {
        let chunk_owned = chunk.to_vec();
        let host_clone = host.to_string();
        let results_clone = results.clone();
        let completed_clone = completed.clone();

        let handle = thread::spawn(move || {
            for &port in &chunk_owned {
                if rate_limit > 0 {
                    let elapsed_ms = completed_clone.load(Ordering::Relaxed) as u64 * 1000 / rate_limit.max(1) as u64;
                    let elapsed = Instant::now().elapsed().as_millis() as u64;
                    if elapsed < elapsed_ms {
                        thread::sleep(Duration::from_millis(elapsed_ms - elapsed));
                    }
                }

                let (open, _filtered) = syn_scan_port(&host_clone, port, timeout_ms);
                if open {
                    let mut res = results_clone.lock().unwrap();
                    res.push((port, open));
                }
                completed_clone.fetch_add(1, Ordering::SeqCst);
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }

    let mut results = results.lock().unwrap().clone();
    results.sort_by_key(|&(p, _)| p);
    results
}

fn grab_banner_with_timeout(host: &str, port: u16, timeout_ms: u64) -> Option<String> {
    let addr_str = format!("{}:{}", host, port);
    let timeout = Duration::from_millis(timeout_ms);
    let addr: SocketAddr = addr_str.parse().ok()?;

    let stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(2000)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(2000)));

    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 256];

    let common_banner_ports: &[u16] = &[21, 22, 25, 80, 110, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5900, 8080, 8443];
    let mut sent_probe = false;

    if common_banner_ports.contains(&port) {
        let mut probe = || -> Option<String> {
            let mut s = TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)).ok()?;
            let _ = s.set_read_timeout(Some(Duration::from_millis(2000)));
            let _ = s.set_write_timeout(Some(Duration::from_millis(2000)));

            let probes: &[(&str, &[u8])] = &[
                ("HTTP", b"GET / HTTP/1.0\r\n\r\n"),
                ("SMTP", b"EHTO scan\r\n"),
                ("FTP", b"\r\n"),
                ("SSH", b"\r\n"),
                ("POP3", b"\r\n"),
                ("IMAP", b"\r\n"),
                ("Generic", b"\r\n"),
            ];

            let mut last = String::new();
            for (_, probe_data) in probes {
                let _ = s.write(probe_data);
                let _ = s.flush();
                let mut inner_buf = [0u8; 512];
                if let Ok(n) = s.read(&mut inner_buf) {
                    if n > 0 {
                        if let Ok(text) = String::from_utf8_lossy(&inner_buf[..n]).to_string() {
                            last = text;
                            if !last.is_empty() {
                                break;
                            }
                        }
                    }
                }
            }
            if last.is_empty() { None } else { Some(last) }
        };
        return probe();
    }

    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
        if buf.len() > 4096 {
            break;
        }
    }

    if buf.is_empty() {
        return None;
    }

    String::from_utf8(buf).ok().map(|s| {
        s.chars()
            .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
            .take(512)
            .collect::<String>()
            .trim()
            .to_string()
    })
}

pub fn shuffle_ports(ports: &[u16]) -> Vec<u16> {
    let mut result = ports.to_vec();
    if result.len() <= 1 {
        return result;
    }

    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let mut state = seed as u64;
    let mut i = result.len();
    while i > 1 {
        i -= 1;
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let j = (state >> 33) as usize % (i + 1);
        result.swap(i, j);
    }

    result
}

pub fn resolve_host(host: &str) -> Option<String> {
    if let Ok(addr) = host.parse::<IpAddr>() {
        return Some(addr.to_string());
    }

    let addr_str = format!("{}:0", host);
    if let Ok(mut addrs) = addr_str.to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            return Some(addr.ip().to_string());
        }
    }

    None
}

pub fn print_results_json(result: &ScanResult) {
    use std::collections::HashMap;

    let mut output = HashMap::new();
    output.insert("host", result.host.clone());
    output.insert("ip", result.ip.clone());
    output.insert("total_ports_scanned", result.total_ports_scanned.to_string());
    output.insert("scan_time_ms", result.scan_time_ms.to_string());
    output.insert("os_guess", result.os_guess.clone().unwrap_or_default());

    let ports_json: Vec<serde_json::Value> = result
        .open_ports
        .iter()
        .map(|s| {
            let mut map = serde_json::Map::new();
            map.insert("port".to_string(), serde_json::Value::Number(serde_json::Number::from(s.port)));
            map.insert("state".to_string(), serde_json::Value::String(format!("{:?}", s.state)));
            map.insert("service".to_string(), serde_json::Value::String(s.service.clone()));
            if let Some(ref p) = s.product {
                map.insert("product".to_string(), serde_json::Value::String(p.clone()));
            }
            if let Some(ref v) = s.version {
                map.insert("version".to_string(), serde_json::Value::String(v.clone()));
            }
            if let Some(ref b) = s.banner {
                let truncated: String = b.chars().take(200).collect();
                map.insert("banner".to_string(), serde_json::Value::String(truncated));
            }
            serde_json::Value::Object(map)
        })
        .collect();

    let mut root = serde_json::Map::new();
    root.insert("host".to_string(), serde_json::Value::String(result.host.clone()));
    root.insert("ip".to_string(), serde_json::Value::String(result.ip.clone()));
    root.insert("total_ports_scanned".to_string(), serde_json::Value::Number(serde_json::Number::from(result.total_ports_scanned as u64)));
    root.insert("scan_time_ms".to_string(), serde_json::Value::Number(serde_json::Number::from(result.scan_time_ms as u64)));
    root.insert("os_guess".to_string(), serde_json::Value::String(result.os_guess.clone().unwrap_or_default()));
    root.insert("open_ports".to_string(), serde_json::Value::Array(ports_json));

    let json_str = serde_json::to_string_pretty(&serde_json::Value::Object(root)).unwrap_or_default();
    println!("{}", json_str);
}

pub fn print_results_table(result: &ScanResult) {
    println!("\n┌────────────────────────────────────────────────────────────┐");
    println!("│ Port Scan Results                                          │");
    println!("├────────────────────────────────────────────────────────────┤");
    println!("│ Host: {:<46} │", result.host);
    println!("│ IP:   {:<46} │", result.ip);
    println!("├──────┬─────────┬──────────┬────────────────────────────────┤");
    println!("│ Port │ State   │ Service  │ Version / Banner               │");
    println!("├──────┼─────────┼──────────┼────────────────────────────────┤");

    let display_count = result.open_ports.len().min(30);
    for svc in result.open_ports.iter().take(display_count) {
        let state_str = match svc.state {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
        };

        let banner_str = if let Some(ref b) = svc.banner {
            let clean: String = b
                .chars()
                .filter(|c| c.is_ascii_graphic() || *c == ' ')
                .take(40)
                .collect();
            clean
        } else if let Some(ref v) = svc.version {
            v.clone()
        } else {
            String::new()
        };

        println!(
            "│ {:<4} │ {:<7} │ {:<8} │ {:<32} │",
            svc.port, state_str, svc.service, banner_str
        );
    }

    if result.open_ports.len() > 30 {
        println!("│ ... {} more open ports not shown                        │", result.open_ports.len() - 30);
    }

    println!("├──────┴─────────┴──────────┴────────────────────────────────┤");
    println!("│ Scanned: {} ports in {} ms", result.total_ports_scanned, result.scan_time_ms);
    println!("│ Open: {} ports", result.open_ports.len());

    if let Some(ref os) = result.os_guess {
        println!("│ OS Guess: {}", os);
    }

    println!("└────────────────────────────────────────────────────────────┘\n");
}

pub fn detect_os_by_ports(host: &str, open_ports: &[u16]) -> Option<String> {
    let port_set: std::collections::BTreeSet<u16> = open_ports.iter().cloned().collect();

    let windows_ports: &[u16] = &[135, 139, 445, 3389, 5985, 5986, 1433, 2179, 47001];
    let linux_ports: &[u16] = &[22, 53, 80, 443, 3306, 5432, 6379, 27017, 8080];
    let mac_ports: &[u16] = &[22, 443, 8443, 5900, 3283, 3689, 5000, 7000, 49152];
    let bsd_ports: &[u16] = &[22, 80, 443, 3306];
    let router_ports: &[u16] = &[22, 23, 53, 80, 443, 161, 179, 520, 1900, 8080];
    let printer_ports: &[u16] = &[21, 80, 443, 515, 631, 9100];
    let iot_camera_ports: &[u16] = &[80, 443, 554, 8000, 8554, 8899];

    let mut windows_score = 0usize;
    let mut linux_score = 0usize;
    let mut mac_score = 0usize;
    let mut bsd_score = 0usize;
    let mut router_score = 0usize;
    let mut printer_score = 0usize;
    let mut camera_score = 0usize;

    for p in &port_set {
        if windows_ports.contains(p) {
            windows_score += 3;
        }
        if linux_ports.contains(p) {
            linux_score += 3;
        }
        if mac_ports.contains(p) {
            mac_score += 3;
        }
        if bsd_ports.contains(p) {
            bsd_score += 1;
        }
        if router_ports.contains(p) {
            router_score += 2;
        }
        if printer_ports.contains(p) {
            printer_score += 2;
        }
        if iot_camera_ports.contains(p) {
            camera_score += 2;
        }
    }

    if port_set.contains(&3389) {
        windows_score += 5;
    }
    if port_set.contains(&135) {
        windows_score += 4;
    }
    if port_set.contains(&139) {
        windows_score += 3;
    }
    if port_set.contains(&445) {
        windows_score += 3;
    }
    if port_set.contains(&5985) || port_set.contains(&5986) {
        windows_score += 4;
    }
    if port_set.contains(&22) && port_set.contains(&23) {
        router_score += 4;
    }
    if port_set.contains(&515) || port_set.contains(&631) {
        printer_score += 5;
    }
    if port_set.contains(&22) && !port_set.contains(&80) && !port_set.contains(&443) {
        return Some("Unix/Linux (SSH-only)".to_string());
    }
    if port_set.contains(&22) && port_set.contains(&80) && port_set.contains(&443) {
        linux_score += 4;
    }
    if port_set.contains(&8443) && port_set.contains(&443) && port_set.contains(&5900) {
        mac_score += 5;
    }
    if port_set.contains(&5432) && port_set.contains(&6379) && port_set.contains(&27017) {
        linux_score += 3;
    }

    let scores = [
        (windows_score, "Windows"),
        (linux_score, "Linux"),
        (mac_score, "macOS/Unix"),
        (bsd_score, "FreeBSD"),
        (router_score, "Router/Network Device"),
        (printer_score, "Printer"),
        (camera_score, "IoT Camera"),
    ];

    let mut scored: Vec<(usize, &str)> = scores.iter().filter(|(s, _)| *s > 0).map(|(s, n)| (*s, *n)).collect();
    if scored.is_empty() {
        if open_ports.len() == 1 && open_ports[0] == 22 {
            return Some("Unix/Linux (SSH-only)".to_string());
        }
        return None;
    }

    scored.sort_by(|a, b| b.0.cmp(&a.0));
    let top_score = scored[0].0;
    let top_matches: Vec<&str> = scored.iter().filter(|(s, _)| *s == top_score).map(|(_, n)| *n).collect();

    if top_matches.len() == 1 {
        Some(top_matches[0].to_string())
    } else {
        Some(format!("{}/Unknown", top_matches.join("/")))
    }
}

pub fn parse_port_range(range: &str) -> Vec<u16> {
    let mut ports = Vec::new();

    for part in range.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if part.contains('-') {
            let sides: Vec<&str> = part.splitn(2, '-').collect();
            if sides.len() == 2 {
                let lo = sides[0].trim().parse::<u16>().unwrap_or(1);
                let hi = sides[1].trim().parse::<u16>().unwrap_or(65535);
                for p in lo..=hi.min(65535) {
                    ports.push(p);
                }
            }
        } else {
            if let Ok(p) = part.parse::<u16>() {
                ports.push(p);
            }
        }
    }

    ports.sort();
    ports.dedup();
    ports
}
