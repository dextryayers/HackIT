use rust_port_scanner::*;
use futures::stream::{self, StreamExt};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const MAX_BANNER: usize = 8192;
const DEFAULT_TIMEOUT_MS: u64 = 2000;
const DEFAULT_WORKERS: usize = 200;

lazy_static::lazy_static! {
    static ref PROBES: HashMap<u16, Vec<u8>> = {
        let mut m = HashMap::new();
        m.insert(21, b"SYST\r\n".to_vec());
        m.insert(22, b"SSH-2.0-HackIT_Probe\r\n".to_vec());
        m.insert(23, b"\r\n".to_vec());
        m.insert(25, b"EHLO hackit.discovery\r\n".to_vec());
        m.insert(53, b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01".to_vec());
        m.insert(80, b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: HackIT-RS/3.0\r\nAccept: */*\r\n\r\n".to_vec());
        m.insert(110, b"CAPA\r\n".to_vec());
        m.insert(111, b"\r\n".to_vec());
        m.insert(135, b"\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00".to_vec());
        m.insert(139, b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00".to_vec());
        m.insert(143, b"A1 CAPABILITY\r\n".to_vec());
        m.insert(161, b"\x30\x2a\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x1d\x02\x02\x01\x4a\x02\x01\x00\x02\x01\x00\x30\x10\x30\x0e\x06\x08\x2b\x06\x01\x02\x01\x01\x02\x00\x00\x00".to_vec());
        m.insert(162, b"".to_vec());
        m.insert(389, b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00".to_vec());
        m.insert(443, b"".to_vec());
        m.insert(445, b"\x00\x00\x00\xa0\xfe\x53\x4d\x42\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
        m.insert(465, b"EHLO hackit.discovery\r\n".to_vec());
        m.insert(500, b"".to_vec());
        m.insert(512, b"".to_vec());
        m.insert(513, b"".to_vec());
        m.insert(514, b"".to_vec());
        m.insert(515, b"".to_vec());
        m.insert(520, b"".to_vec());
        m.insert(521, b"".to_vec());
        m.insert(540, b"".to_vec());
        m.insert(548, b"".to_vec());
        m.insert(554, b"".to_vec());
        m.insert(587, b"EHLO hackit.discovery\r\n".to_vec());
        m.insert(631, b"".to_vec());
        m.insert(636, b"".to_vec());
        m.insert(646, b"".to_vec());
        m.insert(873, b"@RSYNCD: 31.0\n".to_vec());
        m.insert(990, b"".to_vec());
        m.insert(992, b"".to_vec());
        m.insert(993, b"".to_vec());
        m.insert(995, b"".to_vec());
        m.insert(1080, b"\x05\x01\x00".to_vec());
        m.insert(1194, b"".to_vec());
        m.insert(1352, b"".to_vec());
        m.insert(1433, b"\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00".to_vec());
        m.insert(1521, b"\x00\x3c\x00\x00\x01\x00\x00\x00\x01\x32\x01\x2c\x00\x00\x08\x00\x7f\xff\x7f\x08\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
        m.insert(1723, b"\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
        m.insert(1883, b"\x10\x0e\x00\x04\x4d\x51\x54\x54\x04\x02\x00\x3c\x00\x0a\x00\x05".to_vec());
        m.insert(2049, b"".to_vec());
        m.insert(2082, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(2083, b"".to_vec());
        m.insert(2086, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(2087, b"".to_vec());
        m.insert(2181, b"\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
        m.insert(2375, b"GET /containers/json HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(2376, b"".to_vec());
        m.insert(2379, b"GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(2483, b"".to_vec());
        m.insert(2484, b"".to_vec());
        m.insert(2628, b"".to_vec());
        m.insert(3000, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(3128, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(3260, b"\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
        m.insert(3306, b"\x0a\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
        m.insert(3389, b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00".to_vec());
        m.insert(3478, b"".to_vec());
        m.insert(3632, b"".to_vec());
        m.insert(3690, b"(48#)\n".to_vec());
        m.insert(4000, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(4369, b"name\n".to_vec());
        m.insert(4443, b"".to_vec());
        m.insert(4489, b"".to_vec());
        m.insert(4567, b"".to_vec());
        m.insert(4662, b"".to_vec());
        m.insert(4848, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(5000, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(5001, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(5002, b"".to_vec());
        m.insert(5050, b"".to_vec());
        m.insert(5060, b"OPTIONS sip:localhost SIP/2.0\r\nVia: SIP/2.0/UDP hackit.local;branch=z9hG4bK776asdhds\r\nMax-Forwards: 70\r\nTo: <sip:test@localhost>\r\nCSeq: 1 OPTIONS\r\nCall-ID: 123456@hackit\r\nFrom: <sip:test@localhost>;tag=123456\r\nContent-Length: 0\r\n\r\n".to_vec());
        m.insert(5061, b"".to_vec());
        m.insert(5222, b"<stream:stream to='localhost' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>".to_vec());
        m.insert(5342, b"".to_vec());
        m.insert(5432, b"\x00\x00\x00\x08\x04\xd2\x16\x2f".to_vec());
        m.insert(5672, b"AMQP\x00\x00\x09\x01".to_vec());
        m.insert(5900, b"RFB 003.008\n".to_vec());
        m.insert(5984, b"GET / HTTP/1.0\r\n\r\n".to_vec());
        m.insert(5985, b"".to_vec());
        m.insert(5986, b"".to_vec());
        m.insert(6000, b"".to_vec());
        m.insert(6001, b"".to_vec());
        m.insert(6379, b"PING\r\n".to_vec());
        m.insert(6443, b"GET /api HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(6580, b"".to_vec());
        m.insert(6667, b"NICK hackit\r\nUSER hackit 0 * :HackIT Scan\r\n".to_vec());
        m.insert(6881, b"".to_vec());
        m.insert(6969, b"".to_vec());
        m.insert(7001, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(7002, b"".to_vec());
        m.insert(7070, b"".to_vec());
        m.insert(7100, b"".to_vec());
        m.insert(7443, b"".to_vec());
        m.insert(7474, b"GET / HTTP/1.0\r\n\r\n".to_vec());
        m.insert(7547, b"".to_vec());
        m.insert(7741, b"".to_vec());
        m.insert(8000, b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: HackIT-RS/3.0\r\n\r\n".to_vec());
        m.insert(8008, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(8009, b"".to_vec());
        m.insert(8080, b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: HackIT-RS/3.0\r\n\r\n".to_vec());
        m.insert(8081, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(8082, b"".to_vec());
        m.insert(8088, b"".to_vec());
        m.insert(8090, b"".to_vec());
        m.insert(8181, b"".to_vec());
        m.insert(8222, b"".to_vec());
        m.insert(8243, b"".to_vec());
        m.insert(8280, b"".to_vec());
        m.insert(8300, b"".to_vec());
        m.insert(8332, b"".to_vec());
        m.insert(8333, b"".to_vec());
        m.insert(8443, b"".to_vec());
        m.insert(8500, b"GET /v1/agent/self HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(8530, b"".to_vec());
        m.insert(8531, b"".to_vec());
        m.insert(8600, b"".to_vec());
        m.insert(8649, b"".to_vec());
        m.insert(8834, b"GET / HTTP/1.0\r\n\r\n".to_vec());
        m.insert(8888, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(8889, b"".to_vec());
        m.insert(8983, b"GET /solr/ HTTP/1.0\r\n\r\n".to_vec());
        m.insert(9000, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(9001, b"".to_vec());
        m.insert(9042, b"\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
        m.insert(9090, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(9092, b"".to_vec());
        m.insert(9100, b"".to_vec());
        m.insert(9160, b"".to_vec());
        m.insert(9200, b"GET / HTTP/1.0\r\n\r\n".to_vec());
        m.insert(9300, b"".to_vec());
        m.insert(9418, b"".to_vec());
        m.insert(9443, b"".to_vec());
        m.insert(9600, b"".to_vec());
        m.insert(9999, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(10000, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(10001, b"".to_vec());
        m.insert(10009, b"".to_vec());
        m.insert(10010, b"".to_vec());
        m.insert(10050, b"".to_vec());
        m.insert(10051, b"".to_vec());
        m.insert(10250, b"GET /openapi/v2 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer hackit\r\n\r\n".to_vec());
        m.insert(11211, b"stats\r\n".to_vec());
        m.insert(11214, b"".to_vec());
        m.insert(12000, b"".to_vec());
        m.insert(12345, b"".to_vec());
        m.insert(15672, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(16080, b"".to_vec());
        m.insert(16225, b"".to_vec());
        m.insert(16379, b"PING\r\n".to_vec());
        m.insert(16443, b"".to_vec());
        m.insert(16992, b"".to_vec());
        m.insert(16993, b"".to_vec());
        m.insert(17017, b"".to_vec());
        m.insert(18080, b"".to_vec());
        m.insert(18081, b"".to_vec());
        m.insert(18264, b"".to_vec());
        m.insert(20000, b"".to_vec());
        m.insert(21379, b"".to_vec());
        m.insert(21571, b"".to_vec());
        m.insert(22222, b"".to_vec());
        m.insert(23333, b"".to_vec());
        m.insert(24444, b"".to_vec());
        m.insert(24800, b"".to_vec());
        m.insert(25565, b"\xfe\x01".to_vec());
        m.insert(26000, b"".to_vec());
        m.insert(26208, b"".to_vec());
        m.insert(27017, b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00".to_vec());
        m.insert(27018, b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00".to_vec());
        m.insert(27019, b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00".to_vec());
        m.insert(27374, b"".to_vec());
        m.insert(28017, b"".to_vec());
        m.insert(30718, b"".to_vec());
        m.insert(31337, b"".to_vec());
        m.insert(32400, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(32764, b"".to_vec());
        m.insert(32768, b"".to_vec());
        m.insert(32822, b"".to_vec());
        m.insert(33848, b"".to_vec());
        m.insert(34012, b"".to_vec());
        m.insert(36865, b"".to_vec());
        m.insert(37444, b"".to_vec());
        m.insert(37651, b"".to_vec());
        m.insert(37777, b"".to_vec());
        m.insert(38893, b"".to_vec());
        m.insert(39148, b"".to_vec());
        m.insert(40000, b"".to_vec());
        m.insert(40911, b"".to_vec());
        m.insert(41511, b"".to_vec());
        m.insert(42510, b"".to_vec());
        m.insert(44176, b"".to_vec());
        m.insert(44442, b"".to_vec());
        m.insert(44443, b"".to_vec());
        m.insert(44501, b"".to_vec());
        m.insert(44818, b"".to_vec());
        m.insert(45000, b"".to_vec());
        m.insert(45054, b"".to_vec());
        m.insert(45564, b"".to_vec());
        m.insert(45678, b"".to_vec());
        m.insert(45920, b"".to_vec());
        m.insert(47000, b"".to_vec());
        m.insert(47557, b"".to_vec());
        m.insert(47624, b"".to_vec());
        m.insert(47806, b"".to_vec());
        m.insert(47808, b"".to_vec());
        m.insert(48080, b"".to_vec());
        m.insert(49152, b"".to_vec());
        m.insert(49153, b"".to_vec());
        m.insert(49154, b"".to_vec());
        m.insert(49155, b"".to_vec());
        m.insert(49156, b"".to_vec());
        m.insert(49157, b"".to_vec());
        m.insert(49158, b"".to_vec());
        m.insert(49159, b"".to_vec());
        m.insert(49160, b"".to_vec());
        m.insert(49161, b"".to_vec());
        m.insert(49162, b"".to_vec());
        m.insert(49163, b"".to_vec());
        m.insert(49164, b"".to_vec());
        m.insert(49165, b"".to_vec());
        m.insert(49166, b"".to_vec());
        m.insert(49167, b"".to_vec());
        m.insert(49168, b"".to_vec());
        m.insert(49169, b"".to_vec());
        m.insert(49170, b"".to_vec());
        m.insert(49171, b"".to_vec());
        m.insert(49172, b"".to_vec());
        m.insert(49173, b"".to_vec());
        m.insert(49174, b"".to_vec());
        m.insert(49175, b"".to_vec());
        m.insert(49176, b"".to_vec());
        m.insert(49177, b"".to_vec());
        m.insert(49178, b"".to_vec());
        m.insert(49179, b"".to_vec());
        m.insert(49180, b"".to_vec());
        m.insert(49181, b"".to_vec());
        m.insert(49182, b"".to_vec());
        m.insert(49183, b"".to_vec());
        m.insert(49184, b"".to_vec());
        m.insert(49185, b"".to_vec());
        m.insert(49186, b"".to_vec());
        m.insert(49187, b"".to_vec());
        m.insert(49188, b"".to_vec());
        m.insert(49189, b"".to_vec());
        m.insert(49190, b"".to_vec());
        m.insert(49191, b"".to_vec());
        m.insert(49192, b"".to_vec());
        m.insert(49301, b"".to_vec());
        m.insert(49400, b"".to_vec());
        m.insert(49999, b"".to_vec());
        m.insert(50000, b"".to_vec());
        m.insert(50001, b"".to_vec());
        m.insert(50002, b"".to_vec());
        m.insert(50003, b"".to_vec());
        m.insert(50006, b"".to_vec());
        m.insert(50300, b"".to_vec());
        m.insert(50389, b"".to_vec());
        m.insert(50500, b"".to_vec());
        m.insert(50636, b"".to_vec());
        m.insert(50800, b"".to_vec());
        m.insert(51103, b"".to_vec());
        m.insert(51493, b"".to_vec());
        m.insert(52673, b"".to_vec());
        m.insert(52822, b"".to_vec());
        m.insert(52848, b"".to_vec());
        m.insert(52869, b"".to_vec());
        m.insert(54045, b"".to_vec());
        m.insert(54328, b"".to_vec());
        m.insert(55055, b"".to_vec());
        m.insert(55056, b"".to_vec());
        m.insert(55555, b"".to_vec());
        m.insert(55600, b"".to_vec());
        m.insert(56737, b"".to_vec());
        m.insert(56738, b"".to_vec());
        m.insert(57294, b"".to_vec());
        m.insert(57797, b"".to_vec());
        m.insert(58080, b"".to_vec());
        m.insert(60020, b"".to_vec());
        m.insert(60443, b"".to_vec());
        m.insert(60606, b"".to_vec());
        m.insert(61613, b"".to_vec());
        m.insert(61616, b"".to_vec());
        m.insert(62078, b"".to_vec());
        m.insert(63331, b"".to_vec());
        m.insert(64623, b"".to_vec());
        m.insert(64680, b"".to_vec());
        m.insert(65000, b"".to_vec());
        m.insert(65129, b"".to_vec());
        m.insert(65389, b"".to_vec());
        m.insert(65535, b"".to_vec());
        m
    };
}

#[derive(Debug, Clone, Serialize)]
struct ScanResult {
    port: u16,
    status: String,
    service: String,
    banner: String,
    version: String,
    protocol: String,
    ttl: u8,
    response_time_ms: f64,
}

#[derive(Debug, Serialize)]
struct StatusUpdate {
    progress: f64,
    message: String,
}

#[derive(Debug, Serialize)]
struct FinalSummary {
    target: String,
    total_ports: usize,
    open_ports: usize,
    filtered: usize,
    closed: usize,
    elapsed_ms: u64,
}

async fn connect_with_timeout(host: &str, port: u16, timeout_ms: u64) -> Result<TcpStream, String> {
    let ip = resolve_host(host).unwrap_or_else(|| host.to_string());
    let addr = format!("{}:{}", ip, port);
    match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(format!("{}", e)),
        Err(_) => Err("timeout".into()),
    }
}

async fn grab_banner(host: &str, port: u16, timeout_ms: u64) -> String {
    let stream = match connect_with_timeout(host, port, timeout_ms).await {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    let (mut reader, mut writer) = stream.into_split();
    let probe = PROBES.get(&port).cloned().unwrap_or_else(|| b"\r\n".to_vec());
    if !probe.is_empty() {
        let _ = timeout(Duration::from_millis(timeout_ms / 2), writer.write_all(&probe)).await;
        let _ = writer.shutdown().await;
    }
    let mut buf = vec![0u8; MAX_BANNER];
    let banner = match timeout(Duration::from_millis(timeout_ms), reader.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            buf.truncate(n);
            String::from_utf8_lossy(&buf).to_string()
        }
        _ => String::new(),
    };
    banner
}

#[inline]
fn extract_version(service: &str, banner: &str) -> String {
    let b = banner.to_lowercase();
    let markers: Vec<&str> = match service {
        "SSH" | "SSH (Dropbear)" | "SSH (libssh)" => vec!["openssh_", "dropbear_", "libssh_"],
        "Apache" => vec!["apache/"],
        "Nginx" => vec!["nginx/"],
        "IIS" => vec!["microsoft-iis/"],
        "LiteSpeed" => vec!["litespeed/"],
        "Lighttpd" => vec!["lighttpd/"],
        "OpenResty" => vec!["openresty/"],
        "Caddy" => vec!["caddy/"],
        "Tomcat" => vec!["tomcat/"],
        "Gunicorn" => vec!["gunicorn/"],
        "Node.js" => vec!["node.js/"],
        "Jetty" => vec!["jetty/"],
        "Cherokee" => vec!["cherokee/"],
        "vsftpd" => vec!["vsftpd"],
        "ProFTPD" => vec!["proftpd"],
        "Pure-FTPd" => vec!["pure-ftpd"],
        "Postfix" => vec!["postfix"],
        "Exim" => vec!["exim "],
        "Sendmail" => vec!["sendmail "],
        "PHP" => vec!["php/"],
        _ => return String::new(),
    };
    for marker in markers {
        if let Some(pos) = b.find(marker) {
            let start = pos + marker.len();
            let rest = &banner[start..];
            let ver: String = rest.chars().take_while(|c| c.is_ascii_digit() || *c == '.' || *c == 'p' || *c == '_').collect();
            if !ver.is_empty() {
                let clean: String = ver.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
                if !clean.is_empty() { return clean; }
            }
        }
    }
    String::new()
}

async fn scan_single_port(host: &str, port: u16, timeout_ms: u64) -> Option<ScanResult> {
    let start = Instant::now();
    let stream = connect_with_timeout(host, port, timeout_ms).await;
    let connected = stream.is_ok();
    let elapsed = start.elapsed().as_millis() as f64;
    if !connected {
        return None;
    }
    let banner_raw = grab_banner(host, port, timeout_ms).await;
    let banner = sanitize_banner(&banner_raw);
    let service = identify_service(&banner, port);
    let version = extract_version(&service, &banner);
    Some(ScanResult {
        port,
        status: "open".to_string(),
        service,
        banner,
        version,
        protocol: "tcp".to_string(),
        ttl: 64,
        response_time_ms: elapsed,
    })
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} --target <host> --ports <ports> [--timeout <ms>] [--mode connect|syn] [--workers <N>]", args[0]);
        eprintln!("  ports: comma-separated (22,80), ranges (1-1024), top:N, all");
        eprintln!("Example: {} --target scanme.nmap.org --ports 22,80,443 --timeout 2000 --workers 200", args[0]);
        std::process::exit(1);
    }
    let mut target = String::new();
    let mut port_spec = String::new();
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;
    let mut workers = DEFAULT_WORKERS;
    let mut mode = "connect".to_string();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--target" | "-t" => { i += 1; if i < args.len() { target = args[i].clone(); } }
            "--ports" | "-p" => { i += 1; if i < args.len() { port_spec = args[i].clone(); } }
            "--timeout" => { i += 1; if i < args.len() { timeout_ms = args[i].parse().unwrap_or(DEFAULT_TIMEOUT_MS); } }
            "--workers" | "-w" => { i += 1; if i < args.len() { workers = args[i].parse().unwrap_or(DEFAULT_WORKERS); } }
            "--mode" | "-m" => { i += 1; if i < args.len() { mode = args[i].clone(); } }
            _ => {}
        }
        i += 1;
    }
    if target.is_empty() || port_spec.is_empty() {
        eprintln!("Error: --target and --ports are required");
        std::process::exit(1);
    }
    let ports = parse_ports(&port_spec);
    if ports.is_empty() {
        eprintln!("Error: no valid ports specified");
        std::process::exit(1);
    }
    eprintln!("TCP_SCANNER target={} ports={} timeout={}ms workers={} mode={}", target, ports.len(), timeout_ms, workers, mode);
    let total = ports.len();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let processed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let start_time = Instant::now();
    let target_clone = target.clone();
    stream::iter(ports.into_iter())
        .for_each_concurrent(workers, |port| {
            let target = target_clone.clone();
            let tx = tx.clone();
            let processed = Arc::clone(&processed);
            async move {
                let result = scan_single_port(&target, port, timeout_ms).await;
                let count = processed.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                if count % 100 == 0 || count == total {
                    let progress = (count as f64 / total as f64 * 100.0 * 100.0).round() / 100.0;
                    let status = StatusUpdate { progress, message: format!("Scanning port {}/{}", port, total) };
                    eprintln!("STATUS:{}", serde_json::to_string(&status).unwrap());
                }
                if let Some(r) = result {
                    let _ = tx.send(r);
                }
            }
        })
        .await;
    drop(tx);
    let mut final_results: Vec<ScanResult> = Vec::with_capacity(total.min(1000));
    while let Some(r) = rx.recv().await {
        final_results.push(r);
    }
    final_results.sort_by(|a, b| a.port.cmp(&b.port));
    final_results.shrink_to_fit();
    let open_count = final_results.len();
    let filtered = 0;
    let closed = total.saturating_sub(open_count).saturating_sub(filtered);
    let elapsed = start_time.elapsed().as_millis() as u64;
    for r in &final_results {
        println!("RESULT:{}", serde_json::to_string(r).unwrap());
    }
    let summary = FinalSummary {
        target: target.clone(),
        total_ports: total,
        open_ports: open_count,
        filtered,
        closed,
        elapsed_ms: elapsed,
    };
    println!("FINAL:{}", serde_json::to_string(&summary).unwrap());
}
