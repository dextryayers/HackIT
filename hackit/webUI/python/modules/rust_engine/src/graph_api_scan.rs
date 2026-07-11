use crate::common::{GraphApiScanResult, GraphEndpoint, build_client};
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::proto::rr::RecordType;
use tokio::time::{timeout, Duration};

fn make_resolver() -> TokioAsyncResolver {
    let mut cfg = ResolverConfig::default();
    cfg.add_name_server(NameServerConfig::new(
        std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)), 53),
        Protocol::Udp,
    ));
    cfg.add_name_server(NameServerConfig::new(
        std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)), 53),
        Protocol::Tcp,
    ));
    TokioAsyncResolver::tokio(cfg, ResolverOpts::default())
}

async fn has_dns_record(domain: &str, rtype: RecordType) -> bool {
    let resolver = make_resolver();
    timeout(Duration::from_secs(10), resolver.lookup(domain, rtype))
        .await
        .ok()
        .and_then(|r| r.ok())
        .map(|r| !r.is_empty())
        .unwrap_or(false)
}

pub async fn scan(target: &str) -> GraphApiScanResult {
    let client = build_client(15);
    let mut has_office365 = false;
    let mut has_google_workspace = false;
    let mut domains = Vec::new();
    let mut endpoints = Vec::new();
    let mut security_issues = Vec::new();
    let mut error = None;

    // Office 365 DNS checks
    let o365_dns_checks = vec![
        format!("autodiscover.{}", target),
        format!("msoid.{}", target),
        format!("_sipfederationtls._tcp.{}", target),
    ];

    for dns_name in &o365_dns_checks {
        if has_dns_record(dns_name, RecordType::A).await
            || has_dns_record(dns_name, RecordType::AAAA).await
            || has_dns_record(dns_name, RecordType::SRV).await
        {
            has_office365 = true;
            domains.push(dns_name.clone());
        }
    }

    // Google Workspace DNS checks
    let gw_dns_checks = vec![
        format!("_googlechallenge.{}", target),
        format!("_dmarc.{}", target),
    ];

    for dns_name in &gw_dns_checks {
        if has_dns_record(dns_name, RecordType::TXT).await
            || has_dns_record(dns_name, RecordType::A).await
        {
            has_google_workspace = true;
            domains.push(dns_name.clone());
        }
    }

    if let Some(ref client) = client {
        // Autodiscover HTTP check
        let autodiscover_url = format!("https://autodiscover.{}/autodiscover/autodiscover.xml", target);
        match client.get(&autodiscover_url).send().await {
            Ok(resp) => {
                let accessible = resp.status().is_success() || resp.status().as_u16() == 401;
                endpoints.push(GraphEndpoint {
                    url: autodiscover_url.clone(),
                    service: "Autodiscover".into(),
                    accessible,
                    requires_auth: resp.status().as_u16() == 401,
                    provider: "Microsoft".into(),
                });
                if accessible {
                    has_office365 = true;
                    security_issues.push("Autodiscover publicly accessible".into());
                }
            }
            Err(_) => {}
        }

        // Outlook autodiscover
        let outlook_url = "https://outlook.office365.com/autodiscover/autodiscover.xml".to_string();
        match client.get(&outlook_url).send().await {
            Ok(resp) => {
                if resp.status().is_success() || resp.status().as_u16() == 401 {
                    has_office365 = true;
                    endpoints.push(GraphEndpoint {
                        url: outlook_url,
                        service: "Outlook Autodiscover".into(),
                        accessible: true,
                        requires_auth: resp.status().as_u16() == 401,
                        provider: "Microsoft".into(),
                    });
                }
            }
            Err(_) => {}
        }

        // User realm check (information leak)
        let realm_url = format!("https://login.microsoftonline.com/getuserrealm.srf?login={}", target);
        match client.get(&realm_url).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    if let Ok(body) = resp.text().await {
                        if body.contains("Federated") || body.contains("Managed") {
                            has_office365 = true;
                            security_issues.push("User realm information leak".into());
                            endpoints.push(GraphEndpoint {
                                url: realm_url,
                                service: "User Realm".into(),
                                accessible: true,
                                requires_auth: false,
                                provider: "Microsoft".into(),
                            });
                        }
                    }
                }
            }
            Err(_) => {}
        }

        // Google Workspace HTTP checks
        let gw_urls = vec![
            format!("https://mail.google.com/a/{}", target),
            format!("https://www.google.com/a/{}/ServiceLogin", target),
            format!("https://calendar.google.com/a/{}", target),
        ];

        for gw_url in &gw_urls {
            match client.get(gw_url).send().await {
                Ok(resp) => {
                    if resp.status().is_success() || resp.status().as_u16() == 302 || resp.status().as_u16() == 303 {
                        has_google_workspace = true;
                        let accessible = resp.status().is_success();
                        endpoints.push(GraphEndpoint {
                            url: gw_url.clone(),
                            service: "Google Workspace".into(),
                            accessible,
                            requires_auth: !accessible,
                            provider: "Google".into(),
                        });
                    }
                }
                Err(_) => {}
            }
        }

        // Microsoft Graph API endpoint check
        let graph_url = "https://graph.microsoft.com/v1.0/".to_string();
        match client.get(&graph_url).send().await {
            Ok(resp) => {
                if resp.status().is_success() || resp.status().as_u16() == 401 {
                    endpoints.push(GraphEndpoint {
                        url: graph_url,
                        service: "Microsoft Graph API".into(),
                        accessible: true,
                        requires_auth: resp.status().as_u16() == 401,
                        provider: "Microsoft".into(),
                    });
                    if resp.status().is_success() {
                        security_issues.push("Open OAuth endpoints".into());
                    }
                }
            }
            Err(_) => {}
        }

        // Google APIs discovery endpoint
        let google_apis_url = "https://www.googleapis.com/discovery/v1/apis".to_string();
        match client.get(&google_apis_url).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    endpoints.push(GraphEndpoint {
                        url: google_apis_url,
                        service: "Google APIs Discovery".into(),
                        accessible: true,
                        requires_auth: false,
                        provider: "Google".into(),
                    });
                }
            }
            Err(_) => {}
        }

        // Target-specific API endpoint checks
        let target_api_urls = vec![
            format!("https://{}/api/v1.0/graph", target),
            format!("https://{}/graph/api", target),
        ];

        for api_url in &target_api_urls {
            match client.get(api_url).send().await {
                Ok(resp) => {
                    let accessible = resp.status().is_success() || resp.status().as_u16() == 401 || resp.status().as_u16() == 403;
                    if accessible {
                        endpoints.push(GraphEndpoint {
                            url: api_url.clone(),
                            service: if api_url.contains("v1.0") { "Graph API v1.0".into() } else { "Graph API".into() },
                            accessible,
                            requires_auth: resp.status().as_u16() == 401 || resp.status().as_u16() == 403,
                            provider: "Unknown".into(),
                        });
                    }
                }
                Err(_) => {}
            }
        }
    } else {
        error = Some("Failed to create HTTP client".into());
    }

    GraphApiScanResult {
        target: target.to_string(),
        has_office365,
        has_google_workspace,
        domains,
        endpoints,
        security_issues,
        error,
    }
}
