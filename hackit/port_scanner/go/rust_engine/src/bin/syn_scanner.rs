use std::net::{Ipv4Addr, UdpSocket};
use std::time::{Duration, Instant};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

#[repr(C, packed)]
struct IpHdr {
    ver_ihl: u8,
    tos: u8,
    total_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    saddr: u32,
    daddr: u32,
}

#[repr(C, packed)]
struct TcpHdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    doff_res: u16,
    window: u16,
    checksum: u16,
    urg_ptr: u16,
}

#[repr(C, packed)]
struct PseudoHdr {
    saddr: u32,
    daddr: u32,
    zero: u8,
    protocol: u8,
    tcp_len: u16,
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

fn build_syn_packet(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, seq: u32) -> Vec<u8> {
    let ip_hdr_len = 20u8;
    let tcp_hdr_len = 20u8;
    let total_len = (ip_hdr_len + tcp_hdr_len) as u16;
    let mut packet = Vec::with_capacity(total_len as usize);
    let ip = IpHdr {
        ver_ihl: 0x45,
        tos: 0,
        total_len: total_len.to_be(),
        id: (rand::random::<u16>()).to_be(),
        frag_off: (0x4000u16).to_be(),
        ttl: 64,
        protocol: 6,
        checksum: 0,
        saddr: src_ip.to_be(),
        daddr: dst_ip.to_be(),
    };
    let ip_bytes = unsafe {
        std::slice::from_raw_parts(
            &ip as *const IpHdr as *const u8,
            ip_hdr_len as usize,
        )
    };
    let mut ip_data = ip_bytes.to_vec();
    let ip_csum = checksum(&ip_data);
    ip_data[16..18].copy_from_slice(&ip_csum.to_be_bytes());
    packet.extend_from_slice(&ip_data);
    let tcp = TcpHdr {
        source: src_port.to_be(),
        dest: dst_port.to_be(),
        seq: seq.to_be(),
        ack_seq: 0,
        doff_res: (tcp_hdr_len as u16 / 4) << 12,
        window: 65535u16.to_be(),
        checksum: 0,
        urg_ptr: 0,
    };
    let tcp_bytes = unsafe {
        std::slice::from_raw_parts(
            &tcp as *const TcpHdr as *const u8,
            tcp_hdr_len as usize,
        )
    };
    let pseudo = PseudoHdr {
        saddr: src_ip.to_be(),
        daddr: dst_ip.to_be(),
        zero: 0,
        protocol: 6,
        tcp_len: (tcp_hdr_len as u16).to_be(),
    };
    let pseudo_bytes = unsafe {
        std::slice::from_raw_parts(
            &pseudo as *const PseudoHdr as *const u8,
            12,
        )
    };
    let mut csum_data = Vec::new();
    csum_data.extend_from_slice(pseudo_bytes);
    csum_data.extend_from_slice(tcp_bytes);
    let tcp_csum = checksum(&csum_data);
    let mut tcp_data = tcp_bytes.to_vec();
    tcp_data[16..18].copy_from_slice(&tcp_csum.to_be_bytes());
    packet.extend_from_slice(&tcp_data);
    packet
}

fn parse_ports(input: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    match input.trim().to_lowercase().as_str() {
        "all" => return (1..=65535).collect(),
        "top100" => {
            return vec![7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4000,4001,4662,4899,5000,5001,5050,5060,5101,5190,5357,5432,5555,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49154];
        }
        _ => {}
    }
    for part in input.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            let s: u16 = start.parse().unwrap_or(1);
            let e: u16 = end.parse().unwrap_or(65535);
            for p in s..=e {
                ports.push(p);
            }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }
    ports.sort();
    ports.dedup();
    ports
}

fn get_source_ip(dst: u32) -> u32 {
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return u32::from_be_bytes([1,1,1,1]),
    };
    let addr = std::net::SocketAddrV4::new(
        Ipv4Addr::from(dst.to_be_bytes()),
        80,
    );
    if sock.connect(addr).is_err() {
        return u32::from_be_bytes([1,1,1,1]);
    }
    if let Ok(local) = sock.local_addr() {
        if let std::net::SocketAddr::V4(v4) = local {
            return u32::from_be_bytes(v4.ip().octets());
        }
    }
    u32::from_be_bytes([1,1,1,1])
}

fn listen_for_synack(raw_sock: &UdpSocket, target_ports: &[u16], timeout_ms: u64) -> (Vec<u16>, Vec<u16>) {
    let mut open_ports = Vec::new();
    let mut rst_ports = Vec::new();
    let start = Instant::now();
    let deadline = Duration::from_millis(timeout_ms);
    let mut buf = vec![0u8; 65536];
    while start.elapsed() < deadline {
        match raw_sock.recv_from(&mut buf) {
            Ok((n, _src)) => {
                if n < 40 { continue; }
                let src_ip = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
                if src_ip != 0 {
                    let ip_hl = (buf[0] & 0x0F) as usize * 4;
                    if n < ip_hl + 14 { continue; }
                    let dst_port = u16::from_be_bytes([buf[ip_hl + 2], buf[ip_hl + 3]]);
                    let flags = u16::from_be_bytes([buf[ip_hl + 12], buf[ip_hl + 13]]);
                    let syn = (flags & 0x0002) != 0;
                    let ack = (flags & 0x0010) != 0;
                    let rst = (flags & 0x0004) != 0;
                    if syn && ack {
                        if target_ports.contains(&dst_port) {
                            if !open_ports.contains(&dst_port) {
                                open_ports.push(dst_port);
                            }
                        }
                    } else if rst {
                        if target_ports.contains(&dst_port) {
                            if !rst_ports.contains(&dst_port) {
                                rst_ports.push(dst_port);
                            }
                        }
                    }
                }
            }
            Err(_) => {
                std::thread::sleep(Duration::from_micros(100));
            }
        }
    }
    (open_ports, rst_ports)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <host> <ports> [timeout_ms] [concurrent_burst]", args[0]);
        eprintln!("  ports: 22,80,443,1-1024,top100,all");
        eprintln!("Example: {} scanme.nmap.org 22,80,443 2000 5000", args[0]);
        std::process::exit(1);
    }
    if unsafe { libc::geteuid() != 0 } {
        eprintln!("Warning: SYN scan requires root privileges. Results may be limited.");
    }
    let host = args[1].clone();
    let port_spec = args[2].clone();
    let timeout_ms: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(2000);
    let burst: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(5000);
    let ports = parse_ports(&port_spec);
    if ports.is_empty() {
        eprintln!("No valid ports specified");
        std::process::exit(1);
    }
    let dst = std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), 0))
        .ok()
        .and_then(|mut addrs| addrs.find(|a| a.is_ipv4()))
        .map(|a| match a { std::net::SocketAddr::V4(v4) => u32::from_be_bytes(v4.ip().octets()), _ => 0 })
        .unwrap_or(0);
    if dst == 0 {
        eprintln!("Failed to resolve host");
        std::process::exit(1);
    }
    let src = get_source_ip(dst);
    eprintln!(
        "SYN_SCAN target={} ports={} timeout={}ms burst={}",
        host, ports.len(), timeout_ms, burst
    );
    let raw_sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to create raw socket: {}", e);
            std::process::exit(1);
        }
    };
    let start = Instant::now();
    let open_count = Arc::new(AtomicUsize::new(0));
    let total = ports.len();
    for chunk in ports.chunks(burst) {
        let chunk_vec = chunk.to_vec();
        for &port in &chunk_vec {
            let seq = rand::random::<u32>();
            let src_port: u16 = 10000 + rand::random::<u16>() % 55535;
            let pkt = build_syn_packet(src, dst, src_port, port, seq);
            let _ = raw_sock.send(&pkt);
        }
        std::thread::sleep(Duration::from_millis(timeout_ms.min(100)));
    }
    let wait_ms = timeout_ms.max(1000);
    let (open_ports, _rst_ports) = listen_for_synack(&raw_sock, &ports, wait_ms);
    let elapsed = start.elapsed().as_millis() as u64;
    for &p in &open_ports {
        println!("RESULT:{{\"port\":{},\"state\":1,\"scan_type\":\"syn\"}}", p);
    }
    eprintln!(
        "FINAL:{{\"target\":\"{}\",\"total\":{},\"open\":{},\"elapsed_ms\":{}}}",
        host, total, open_ports.len(), elapsed
    );
}
