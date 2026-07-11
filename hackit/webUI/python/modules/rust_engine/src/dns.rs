use crate::common::DnsResult;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::proto::rr::RecordType;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

pub async fn enumerate(domain: &str) -> DnsResult {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());
    let google = TokioAsyncResolver::tokio(ResolverConfig::google(), ResolverOpts::default());
    let mut r = DnsResult::default();

    macro_rules! lookup {
        ($rt:ident, $ty:ident => $field:ident) => {
            if let Ok(answers) = $rt.lookup(domain, RecordType::$ty).await {
                for ans in answers.iter() { r.$field.push(ans.to_string()); }
            }
        };
    }

    lookup!(resolver, A => a);
    lookup!(resolver, AAAA => aaaa);
    lookup!(resolver, MX => mx);
    lookup!(resolver, NS => ns);
    lookup!(resolver, TXT => txt);
    lookup!(resolver, CNAME => cname);

    if let Ok(answers) = resolver.lookup(domain, RecordType::SOA).await {
        for ans in answers.iter() { r.soa = Some(ans.to_string()); break; }
    }

    let srv_services = ["_sip._tcp", "_sips._tcp", "_xmpp._tcp", "_xmpps._tcp", "_imap._tcp", "_ldap._tcp", "_kerberos._tcp", "_caldav._tcp", "_carddav._tcp", "_jabber._tcp", "_submission._tcp"];
    for svc in &srv_services {
        let srv_name = format!("{}.{}", svc, domain);
        if let Ok(answers) = resolver.lookup(&srv_name, RecordType::SRV).await {
            for ans in answers.iter() { r.srv.push(format!("{} {}", svc, ans)); }
        }
    }

    if let Ok(answers) = resolver.lookup(domain, RecordType::PTR).await {
        for ans in answers.iter() { r.ptr.push(ans.to_string()); }
    }

    if let Ok(answers) = resolver.lookup(domain, RecordType::CAA).await {
        for ans in answers.iter() { r.caa.push(ans.to_string()); }
    }

    // Fallback: try google resolver for records that might be blocked
    if r.a.is_empty() {
        lookup!(google, A => a);
    }

    // DNS Zone Transfer attempt
    let ns_list = r.ns.clone();
    for ns in &ns_list {
        let ns_host = ns.trim_end_matches('.');
        if let Ok(addr) = format!("{}:53", ns_host).parse::<SocketAddr>() {
            if TcpStream::connect_timeout(&addr, Duration::from_secs(3)).is_ok() {
                r.zone_transfer = Some(format!("Zone transfer possible on {}", ns_host));
            }
        }
    }

    r
}
