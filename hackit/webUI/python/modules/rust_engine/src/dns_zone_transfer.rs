use crate::common::*;
use crate::{progress, progress_done};
use std::net::ToSocketAddrs;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use trust_dns_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use trust_dns_proto::rr::RecordType;
use trust_dns_proto::rr::domain::Name;
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

const DNS_PORT: u16 = 53;
const CONN_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(15);
const RESOLVER_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn enumerate(domain: &str) -> DnsZoneTransferResult {
    progress!("dns_zone_transfer", "running");

    let mut result = DnsZoneTransferResult {
        domain: domain.into(),
        ..Default::default()
    };

    let mut resolver_opts = ResolverOpts::default();
    resolver_opts.timeout = RESOLVER_TIMEOUT;
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        resolver_opts,
    );

    let domain_name = match Name::from_str(domain) {
        Ok(n) => n,
        Err(_) => {
            progress_done!("dns_zone_transfer");
            return result;
        }
    };

    if let Ok(ns_resp) = resolver.ns_lookup(domain).await {
        for r in ns_resp.iter() {
            result.nameservers.push(r.to_string().trim_end_matches('.').to_string());
        }
    }

    if let Ok(soa_resp) = resolver.soa_lookup(domain).await {
        for r in soa_resp.iter() {
            result.records.push(format!("SOA: {}", r));
        }
    }

    if let Ok(dnskey_resp) = resolver.lookup(domain_name.clone(), RecordType::DNSKEY).await {
        result.dnssec_enabled = dnskey_resp.iter().count() > 0;
    }

    if !result.nameservers.is_empty() {
        for ns in &result.nameservers {
            match attempt_axfr(ns, &domain_name).await {
                Ok(records) if !records.is_empty() => {
                    result.zone_transfer_possible = true;
                    result.records.extend(records);
                    break;
                }
                _ => continue,
            }
        }
    }

    progress_done!("dns_zone_transfer");
    result
}

async fn attempt_axfr(nameserver: &str, domain_name: &Name) -> Result<Vec<String>, String> {
    let addr_str = format!("{}:{}", nameserver, DNS_PORT);
    let addr = addr_str
        .to_socket_addrs()
        .map_err(|e| format!("addr resolution failed for {}: {}", nameserver, e))?
        .next()
        .ok_or_else(|| format!("no address resolved for {}", nameserver))?;

    let stream = timeout(CONN_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| format!("connect timeout to {}", nameserver))?
        .map_err(|e| format!("connect failed to {}:53: {}", nameserver, e))?;

    let (mut reader, mut writer) = stream.into_split();

    let mut query = Message::new();
    query.set_message_type(MessageType::Query);
    query.set_op_code(OpCode::Query);
    query.set_recursion_desired(false);
    query.add_query(Query::query(domain_name.clone(), RecordType::AXFR));

    let query_bytes = query
        .to_bytes()
        .map_err(|e| format!("failed to encode AXFR query: {}", e))?;

    let msg_len = query_bytes.len();
    if msg_len > 65535 {
        return Err("AXFR query too large".to_string());
    }

    let mut len_prefixed = Vec::with_capacity(2 + msg_len);
    len_prefixed.extend_from_slice(&(msg_len as u16).to_be_bytes());
    len_prefixed.extend_from_slice(&query_bytes);

    timeout(IO_TIMEOUT, writer.write_all(&len_prefixed))
        .await
        .map_err(|_| format!("write timeout to {}", nameserver))?
        .map_err(|e| format!("write to {}:53 failed: {}", nameserver, e))?;

    let mut records: Vec<String> = Vec::new();

    loop {
        let mut len_buf = [0u8; 2];
        let read_result = timeout(IO_TIMEOUT, reader.read_exact(&mut len_buf)).await;

        let msg_len = match read_result {
            Ok(Ok(_)) => u16::from_be_bytes(len_buf) as usize,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Ok(Err(e)) => {
                return Err(format!("read error from {}:53: {}", nameserver, e));
            }
            Err(_) => break,
        };

        if msg_len == 0 || msg_len > 65535 {
            continue;
        }

        let mut msg_buf = vec![0u8; msg_len];
        timeout(IO_TIMEOUT, reader.read_exact(&mut msg_buf))
            .await
            .map_err(|_| format!("read timeout from {}", nameserver))?
            .map_err(|e| format!("read error from {}:53: {}", nameserver, e))?;

        let response = match Message::from_bytes(&msg_buf) {
            Ok(msg) => msg,
            Err(_) => continue,
        };

        match response.response_code() {
            ResponseCode::NoError => {}
            ResponseCode::Refused | ResponseCode::NotImp | ResponseCode::ServFail => {
                return Ok(records);
            }
            _ => return Ok(records),
        }

        for answer in response.answers() {
            let rtype = answer.record_type();
            let name = answer.name().to_string();
            let ttl = answer.ttl();
            let rdata = match answer.data() {
                Some(d) => format!("{}", d),
                None => String::new(),
            };
            records.push(format!("{} {} {} {}", name, rtype, ttl, rdata));
        }
    }

    Ok(records)
}
