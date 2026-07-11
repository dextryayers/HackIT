use crate::common::DnsResult;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::proto::op::{Message, OpCode, MessageType, Query, ResponseCode};
use trust_dns_resolver::proto::rr::Name;
use trust_dns_resolver::proto::serialize::binary::{BinEncoder, BinEncodable};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const AXFR_CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const AXFR_READ_TIMEOUT: Duration = Duration::from_secs(6);

fn make_resolver(env_key: &str, fallback: ResolverConfig) -> TokioAsyncResolver {
    if let Ok(ip_str) = std::env::var(env_key) {
        if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
            let addr = SocketAddr::new(ip, 53);
            let mut cfg = ResolverConfig::new();
            cfg.add_name_server(NameServerConfig::new(addr, Protocol::Udp));
            cfg.add_name_server(NameServerConfig::new(addr, Protocol::Tcp));
            return TokioAsyncResolver::tokio(cfg, ResolverOpts::default());
        }
    }
    TokioAsyncResolver::tokio(fallback, ResolverOpts::default())
}

async fn lookup_timeout(
    resolver: &TokioAsyncResolver,
    domain: &str,
    rtype: RecordType,
) -> Vec<String> {
    match timeout(QUERY_TIMEOUT, resolver.lookup(domain, rtype)).await {
        Ok(Ok(answers)) => answers.iter().map(|a| a.to_string()).collect(),
        _ => Vec::new(),
    }
}

pub async fn enumerate(domain: &str) -> DnsResult {
    let resolver = make_resolver("CLOUDFLARE_DNS", ResolverConfig::cloudflare());
    let google = make_resolver("GOOGLE_DNS", ResolverConfig::google());
    let mut r = DnsResult::default();

    r.a = lookup_timeout(&resolver, domain, RecordType::A).await;
    r.aaaa = lookup_timeout(&resolver, domain, RecordType::AAAA).await;
    r.mx = lookup_timeout(&resolver, domain, RecordType::MX).await;
    r.ns = lookup_timeout(&resolver, domain, RecordType::NS).await;
    r.txt = lookup_timeout(&resolver, domain, RecordType::TXT).await;
    r.cname = lookup_timeout(&resolver, domain, RecordType::CNAME).await;
    r.caa = lookup_timeout(&resolver, domain, RecordType::CAA).await;
    r.sshfp = lookup_timeout(&resolver, domain, RecordType::SSHFP).await;
    r.tlsa = lookup_timeout(&resolver, domain, RecordType::TLSA).await;
    r.ds = lookup_timeout(&resolver, domain, RecordType::DS).await;
    r.dnskey = lookup_timeout(&resolver, domain, RecordType::DNSKEY).await;
    r.nsec = lookup_timeout(&resolver, domain, RecordType::NSEC).await;
    r.nsec3 = lookup_timeout(&resolver, domain, RecordType::NSEC3).await;

    if let Ok(Ok(answers)) = timeout(QUERY_TIMEOUT, resolver.lookup(domain, RecordType::SOA)).await {
        if let Some(ans) = answers.iter().next() {
            r.soa = Some(ans.to_string());
        }
    }

    let srv_services = [
        "_sip._tcp", "_sips._tcp", "_xmpp._tcp", "_xmpps._tcp",
        "_imap._tcp", "_ldap._tcp", "_kerberos._tcp", "_caldav._tcp",
        "_carddav._tcp", "_jabber._tcp", "_submission._tcp",
    ];
    for svc in &srv_services {
        let srv_name = format!("{}.{}", svc, domain);
        let answers = lookup_timeout(&resolver, &srv_name, RecordType::SRV).await;
        for ans in answers {
            r.srv.push(format!("{} {}", svc, ans));
        }
    }

    r.ptr = lookup_timeout(&resolver, domain, RecordType::PTR).await;

    r.dnssec = Some(if !r.dnskey.is_empty() || !r.ds.is_empty() {
        "enabled".into()
    } else {
        "absent".into()
    });

    if r.a.is_empty() {
        r.a = lookup_timeout(&google, domain, RecordType::A).await;
    }

    let ns_list = r.ns.clone();
    for ns in &ns_list {
        let ns_host = ns.trim_end_matches('.');
        if let Some(result) = attempt_axfr(domain, ns_host).await {
            r.zone_transfer = Some(result);
            break;
        }
    }

    r
}

async fn attempt_axfr(domain: &str, ns_host: &str) -> Option<String> {
    let addr: SocketAddr = format!("{}:53", ns_host).parse().ok()?;

    let stream = timeout(AXFR_CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?;
    let mut stream = stream.ok()?;

    let mut msg = Message::new();
    let id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_micros()
        % 65535) as u16;
    msg.set_id(id);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(false);

    let name = Name::from_str(domain).ok()?;
    msg.add_query(Query::query(name, RecordType::AXFR));

    let mut buf = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut buf);
    msg.emit(&mut encoder).ok()?;

    let len = buf.len() as u16;
    stream.write_all(&len.to_be_bytes()).await.ok()?;
    stream.write_all(&buf).await.ok()?;

    let mut len_buf = [0u8; 2];
    if timeout(AXFR_READ_TIMEOUT, stream.read_exact(&mut len_buf))
        .await
        .ok()
        .and_then(|r| r.ok())
        .is_none()
    {
        return None;
    }

    let response_len = u16::from_be_bytes(len_buf) as usize;
    if response_len == 0 {
        return None;
    }

    let mut response = vec![0u8; response_len];
    stream.read_exact(&mut response).await.ok()?;

    if let Ok(response_msg) = Message::from_vec(&response) {
        if response_msg.response_code() == ResponseCode::NoError
            && response_msg.answer_count() > 0
        {
            return Some(format!(
                "Zone transfer possible on {} ({} records)",
                ns_host,
                response_msg.answer_count()
            ));
        }
    }

    Some(format!(
        "Zone transfer response from {} ({} bytes)",
        ns_host, response_len
    ))
}
