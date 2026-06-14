use std::env;
use trust_dns_resolver::config::*;
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::Resolver;
use reqwest::blocking::Client;
use std::time::Duration;
use once_cell::sync::Lazy;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Signature {
    platform: String,
    cname: Vec<String>,
    fingerprints: Vec<String>,
    vulnerable: bool,
}

static SIGNATURES: Lazy<Vec<Signature>> = Lazy::new(|| {
    let data = r#"[
        {"platform":"GitHub Pages","cname":["github.io","github.com"],"fingerprints":["There isn't a GitHub Pages site here"],"vulnerable":true},
        {"platform":"Heroku","cname":["herokudns.com","herokuapp.com"],"fingerprints":["no such app","No such app"],"vulnerable":true},
        {"platform":"Azure","cname":["azurewebsites.net","cloudapp.net","azureedge.net","windows.net","trafficmanager.net"],"fingerprints":["The resource you are looking for has been removed","Web Site not found"],"vulnerable":true},
        {"platform":"AWS S3","cname":["s3.amazonaws.com","s3-website"],"fingerprints":["The specified bucket does not exist","NoSuchBucket"],"vulnerable":true},
        {"platform":"Shopify","cname":["myshopify.com"],"fingerprints":["Sorry, this shop is currently unavailable"],"vulnerable":true},
        {"platform":"Zendesk","cname":["zendesk.com"],"fingerprints":["Help Center Closed","No help center found"],"vulnerable":true},
        {"platform":"Ghost","cname":["ghost.io"],"fingerprints":["The thing you were looking for is no longer here"],"vulnerable":true},
        {"platform":"WPEngine","cname":["wpengine.com"],"fingerprints":["The site you were looking for could not be found"],"vulnerable":true},
        {"platform":"CloudFront","cname":["cloudfront.net"],"fingerprints":["Bad request"],"vulnerable":true},
        {"platform":"Netlify","cname":["netlify.app","netlify.com"],"fingerprints":["Not Found - Netlify","404 not found"],"vulnerable":true},
        {"platform":"Tumblr","cname":["tumblr.com"],"fingerprints":["There's nothing here"],"vulnerable":true},
        {"platform":"WordPress","cname":["wordpress.com"],"fingerprints":["Do you want to register"],"vulnerable":true},
        {"platform":"Unbounce","cname":["unbouncepages.com"],"fingerprints":["The page you were looking for doesn't exist"],"vulnerable":true},
        {"platform":"Surge","cname":["surge.sh"],"fingerprints":["project not found"],"vulnerable":true},
        {"platform":"Bitbucket","cname":["bitbucket.io"],"fingerprints":["Repository not found"],"vulnerable":true},
        {"platform":"Pantheon","cname":["pantheonsite.io"],"fingerprints":["The gods are wise"],"vulnerable":true},
        {"platform":"Intercom","cname":["custom.intercom.help"],"fingerprints":["This page is out of order"],"vulnerable":true},
        {"platform":"HelpScout","cname":["helpscoutdocs.com"],"fingerprints":["No help articles found"],"vulnerable":true},
        {"platform":"Cargo","cname":["cargocollective.com"],"fingerprints":["404 Not Found"],"vulnerable":true},
        {"platform":"Strikingly","cname":["strikingly.com","strikinglycdn.com"],"fingerprints":["page not found"],"vulnerable":true},
        {"platform":"UserVoice","cname":["uservoice.com"],"fingerprints":["This UserVoice subdomain is currently available"],"vulnerable":true},
        {"platform":"Statuspage","cname":["statuspage.io"],"fingerprints":["The page you are looking for doesn't exist"],"vulnerable":true},
        {"platform":"ReadTheDocs","cname":["readthedocs.io"],"fingerprints":["This page does not exist yet"],"vulnerable":true},
        {"platform":"Airee","cname":["airee.ru"],"fingerprints":["hellodomain.ru"],"vulnerable":true},
        {"platform":"Fly","cname":["fly.dev"],"fingerprints":["404 Not Found"],"vulnerable":true},
        {"platform":"Vercel","cname":["vercel.app","vercel.com"],"fingerprints":["The deployment could not be found","404: Not Found"],"vulnerable":true}
    ]"#;
    serde_json::from_str(data).unwrap_or_else(|_| vec![])
});

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: subdomain_takeover <domain1,domain2,...>");
        std::process::exit(1);
    }

    let domains_str = &args[1];
    let domain_list: Vec<&str> = domains_str.split(',').collect();

    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())
        .unwrap_or_else(|_| Resolver::from_system_conf().unwrap());

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    for domain in &domain_list {
        let d = domain.trim();
        let result = check_takeover(d, &resolver, &client);
        println!("RESULT:{}", result);
    }

    let final_json = serde_json::json!({"total_checked": domain_list.len()});
    println!("FINAL:{}", final_json);
}

fn check_takeover(domain: &str, resolver: &Resolver, client: &Client) -> serde_json::Value {
    let mut cname_chain = Vec::new();
    let mut current = domain.to_string();

    for _ in 0..4 {
        match resolver.lookup(&current, RecordType::CNAME) {
            Ok(lookup) => {
                if let Some(c) = lookup.iter().filter_map(|r| r.as_cname()).next() {
                    let cname = c.to_string().trim_end_matches('.').to_string();
                    if cname == current { break; }
                    cname_chain.push(cname.clone());
                    current = cname;
                } else { break; }
            }
            Err(_) => break,
        }
    }

    if cname_chain.is_empty() {
        return serde_json::json!({
            "subdomain": domain,
            "takeover": false,
            "platform": "",
            "cname_chain": [],
            "status": "safe"
        });
    }

    let final_cname = cname_chain.last().unwrap();

    for sig in SIGNATURES.iter() {
        if !sig.cname.iter().any(|c| final_cname.contains(c)) {
            continue;
        }

        match resolver.lookup_ip(final_cname) {
            Ok(_) => {
                let http_vuln = verify_http(domain, &sig.fingerprints, client);
                if http_vuln {
                    return serde_json::json!({
                        "subdomain": domain,
                        "takeover": true,
                        "platform": sig.platform,
                        "cname_chain": cname_chain,
                        "status": "vulnerable",
                        "detail": format!("{} takeover on {}", sig.platform, domain)
                    });
                }
                return serde_json::json!({
                    "subdomain": domain,
                    "takeover": false,
                    "platform": sig.platform,
                    "cname_chain": cname_chain,
                    "status": "claimed",
                    "detail": format!("CNAME resolves - likely claimed by {}", sig.platform)
                });
            }
            Err(_) => {
                return serde_json::json!({
                    "subdomain": domain,
                    "takeover": true,
                    "platform": sig.platform,
                    "cname_chain": cname_chain,
                    "status": "vulnerable",
                    "detail": format!("{} takeover likely (dangling CNAME)", sig.platform)
                });
            }
        }
    }

    serde_json::json!({
        "subdomain": domain,
        "takeover": false,
        "platform": "",
        "cname_chain": cname_chain,
        "status": "unmatched",
        "detail": format!("CNAME chain: {} (no signature matched)", cname_chain.join(" -> "))
    })
}

fn verify_http(domain: &str, fingerprints: &[String], client: &Client) -> bool {
    for proto in &["https://", "http://"] {
        let url = format!("{}{}", proto, domain);
        if let Ok(resp) = client.get(&url).send() {
            if let Ok(body) = resp.text() {
                for fp in fingerprints {
                    if body.contains(fp) {
                        return true;
                    }
                }
            }
        }
    }
    false
}
