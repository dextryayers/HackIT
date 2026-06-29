use rayon::prelude::*;
use std::net::{Ipv4Addr, UdpSocket, ToSocketAddrs};
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicUsize, Ordering};
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

fn tcp_checksum(ip: &IpHdr, tcp: &TcpHdr, tcp_len: u16) -> u16 {
    let pseudo = PseudoHdr {
        saddr: ip.saddr,
        daddr: ip.daddr,
        zero: 0,
        protocol: 6,
        tcp_len: tcp_len.to_be(),
    };
    let pseudo_bytes = unsafe {
        std::slice::from_raw_parts(&pseudo as *const _ as *const u8, std::mem::size_of::<PseudoHdr>())
    };
    let tcp_bytes = unsafe {
        std::slice::from_raw_parts(tcp as *const _ as *const u8, tcp_len as usize)
    };
    let mut data = Vec::with_capacity(pseudo_bytes.len() + tcp_bytes.len());
    data.extend_from_slice(pseudo_bytes);
    data.extend_from_slice(tcp_bytes);
    checksum(&data)
}

fn send_syn(sock: &UdpSocket, src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, seq: u32) {
    let ip = IpHdr {
        ver_ihl: 0x45,
        tos: 0,
        total_len: (20u16 + 20u16).to_be(),
        id: rand::random::<u16>().to_be(),
        frag_off: (0x4000u16).to_be(),
        ttl: 64,
        protocol: 6,
        checksum: 0,
        saddr: u32::from(src).to_be(),
        daddr: u32::from(dst).to_be(),
    };

    let mut tcp = TcpHdr {
        source: sport.to_be(),
        dest: dport.to_be(),
        seq: seq.to_be(),
        ack_seq: 0,
        doff_res: (0x50u16).to_be(),
        window: 65535u16.to_be(),
        checksum: 0,
        urg_ptr: 0,
    };

    let tcp_len = 20u16;
    tcp.checksum = tcp_checksum(&ip, &tcp, tcp_len);

    let mut packet = Vec::with_capacity(40);
    let ip_bytes = unsafe {
        std::slice::from_raw_parts(&ip as *const _ as *const u8, 20)
    };
    let tcp_bytes = unsafe {
        std::slice::from_raw_parts(&tcp as *const _ as *const u8, 20)
    };
    packet.extend_from_slice(ip_bytes);
    packet.extend_from_slice(tcp_bytes);

    let dst_sa: std::net::SocketAddr = (dst, 0).into();
    let _ = sock.send_to(&packet, dst_sa);
}

fn listen_for_synack(sock: &UdpSocket, expected_dst: Ipv4Addr, expected_sport: u16, expected_seq: u32, ports: &[u16], timeout_ms: u64) -> Vec<u16> {
    let mut open = Vec::new();
    let start = Instant::now();
    let mut buf = [0u8; 65535];

    while start.elapsed() < Duration::from_millis(timeout_ms) {
        if let Ok((n, _)) = sock.recv_from(&mut buf) {
            if n < 40 { continue; }
            let ip = unsafe { &*(buf.as_ptr() as *const IpHdr) };
            if u32::from_be(ip.saddr) != u32::from(expected_dst) { continue; }
            if ip.protocol != 6 { continue; }
            let ip_hl = (ip.ver_ihl & 0x0F) as usize * 4;
            if n < ip_hl + 20 { continue; }
            let tcp = unsafe { &*(buf.as_ptr().add(ip_hl) as *const TcpHdr) };
            let flags = u16::from_be(tcp.doff_res) & 0x3F;
            if flags & 0x12 != 0x12 { continue; }
            let dport = u16::from_be(tcp.dest);
            if dport != expected_sport { continue; }
            let sport = u16::from_be(tcp.source);
            if ports.contains(&sport) {
                open.push(sport);
            }
        }
    }
    open
}

pub fn run_syn_scan(target: &str, port_spec: &str, rate: u64, json: bool) {
    let dst: Ipv4Addr = match target.parse() {
        Ok(ip) => ip,
        Err(_) => {
            match format!("{}:0", target).to_socket_addrs() {
                Ok(mut addrs) => {
                    if let Some(sa) = addrs.next() {
                        match sa.ip() {
                            std::net::IpAddr::V4(v4) => v4,
                            _ => Ipv4Addr::new(127,0,0,1),
                        }
                    } else {
                        Ipv4Addr::new(127,0,0,1)
                    }
                }
                Err(_) => Ipv4Addr::new(127,0,0,1),
            }
        }
    };

    let ports = parse_ports_syn(port_spec);
    let total = ports.len();

    if !json {
        println!("[RUST-SYN] Scanning {} — {} ports @ {} pkts/s", dst, total, rate);
    }

    let src = Ipv4Addr::new(10, 0, 0, 1);
    let sock = UdpSocket::bind("0.0.0.0:0").expect("UDP socket bind failed");

    let seq_base = rand::random::<u32>();
    let found = Arc::new(AtomicUsize::new(0));

    let chunk_size = (rate as usize / 100).max(1);
    let batch_start = Instant::now();

    ports.par_chunks(chunk_size).for_each(|chunk| {
        let sport = rand::random::<u16>() | 0x4000;
        for &dport in chunk {
            let seq = seq_base.wrapping_add(dport as u32);
            send_syn(&sock, src, dst, sport, dport, seq);
        }
    });

    let open = listen_for_synack(&sock, dst, 0, seq_base, &ports, 2000);
    let elapsed = batch_start.elapsed();
    found.store(open.len(), Ordering::Relaxed);

    if json {
        let output = serde_json::to_string(&serde_json::json!({
            "engine": "rust-syn",
            "target": target,
            "total": total,
            "open": open.len(),
            "duration_ms": elapsed.as_millis(),
            "open_ports": open,
        })).unwrap_or_default();
        println!("FINAL:{}", output);
    } else {
        println!("[RUST-SYN] {} open ports found in {:?}", open.len(), elapsed);
        for p in &open {
            println!("  PORT={}", p);
        }
    }
}

fn parse_ports_syn(spec: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            let s: u16 = start.parse().unwrap_or(1);
            let e: u16 = end.parse().unwrap_or(65535);
            for p in s..=e.min(65535) {
                ports.push(p);
            }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }
    ports
}
