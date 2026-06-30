use ipnetwork::IpNetwork;
use std::mem;
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

#[repr(C, packed)]
struct IcmpHdr {
    icmp_type: u8,
    code: u8,
    checksum: u16,
    id: u16,
    seq: u16,
    payload: [u8; 56],
}

fn icmp_checksum(data: &[u8]) -> u16 {
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

pub fn ping_icmp(host: IpAddr, timeout_ms: u64) -> bool {
    let dst = match host {
        IpAddr::V4(v4) => v4,
        _ => return false,
    };
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if fd < 0 {
        return false;
    }
    let pid = (std::process::id() & 0xFFFF) as u16;
    let mut hdr = IcmpHdr {
        icmp_type: 8,
        code: 0,
        checksum: 0,
        id: pid,
        seq: 1,
        payload: [0u8; 56],
    };
    let slice = unsafe {
        std::slice::from_raw_parts(&hdr as *const _ as *const u8, mem::size_of::<IcmpHdr>())
    };
    let csum = icmp_checksum(slice);
    hdr.checksum = csum;
    let pkt = unsafe {
        std::slice::from_raw_parts(&hdr as *const _ as *const u8, mem::size_of::<IcmpHdr>())
    };
    let dst_addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(dst).to_be(),
        },
        sin_zero: [0; 8],
    };
    let sent = unsafe {
        libc::sendto(
            fd,
            pkt.as_ptr() as *const libc::c_void,
            pkt.len(),
            0,
            &dst_addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    if sent <= 0 {
        unsafe { libc::close(fd); }
        return false;
    }
    let tv = libc::timeval {
        tv_sec: (timeout_ms / 1000) as i64,
        tv_usec: ((timeout_ms % 1000) * 1000) as i64,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            mem::size_of::<libc::timeval>() as u32,
        );
    }
    let mut recv_buf = [0u8; 1024];
    let mut src_addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    let mut addr_len: libc::socklen_t = mem::size_of::<libc::sockaddr_in>() as u32;
    let n = unsafe {
        libc::recvfrom(
            fd,
            recv_buf.as_mut_ptr() as *mut libc::c_void,
            recv_buf.len(),
            0,
            &mut src_addr as *mut _ as *mut libc::sockaddr,
            &mut addr_len,
        )
    };
    unsafe { libc::close(fd); }
    if n < 20 {
        return false;
    }
    let ip_hl = ((recv_buf[0] & 0x0F) * 4) as usize;
    let icmp_off = ip_hl;
    if (n as usize) < icmp_off + 8 {
        return false;
    }
    recv_buf[icmp_off] == 0 && recv_buf[icmp_off + 1] == 0
}

pub async fn ping_tcp(host: IpAddr, port: u16, timeout_ms: u64) -> bool {
    let addr = format!("{}:{}", host, port);
    timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr))
        .await
        .ok()
        .and_then(|r| r.ok())
        .is_some()
}

pub async fn ping_udp(host: IpAddr, port: u16, timeout_ms: u64) -> bool {
    let addr = format!("{}:{}", host, port);
    let sock = UdpSocket::bind("0.0.0.0:0").await;
    if sock.is_err() {
        return false;
    }
    let sock = sock.unwrap();
    if sock.connect(&addr).await.is_err() {
        return false;
    }
    if sock.send(b"\x00").await.is_err() {
        return false;
    }
    let mut buf = [0u8; 1];
    timeout(Duration::from_millis(timeout_ms), sock.recv(&mut buf))
        .await
        .ok()
        .and_then(|r| r.ok())
        .is_some()
}

pub async fn discover_hosts(subnet: &str, method: &str) -> Vec<IpAddr> {
    let network: IpNetwork = match subnet.parse() {
        Ok(n) => n,
        Err(_) => return vec![],
    };
    let mut live = Vec::new();
    let mut tasks = Vec::new();
    for host in network.iter() {
        let m = method.to_string();
        tasks.push(tokio::spawn(async move {
            match m.as_str() {
                "icmp" => {
                    if ping_icmp(host, 1000) {
                        Some(host)
                    } else {
                        None
                    }
                }
                "tcp" => {
                    if ping_tcp(host, 80, 1000).await {
                        Some(host)
                    } else {
                        None
                    }
                }
                "udp" => {
                    if ping_udp(host, 53, 1000).await {
                        Some(host)
                    } else {
                        None
                    }
                }
                _ => {
                    if ping_tcp(host, 80, 1000).await {
                        Some(host)
                    } else {
                        None
                    }
                }
            }
        }));
    }
    for task in tasks {
        if let Ok(Some(ip)) = task.await {
            live.push(ip);
        }
    }
    live
}
