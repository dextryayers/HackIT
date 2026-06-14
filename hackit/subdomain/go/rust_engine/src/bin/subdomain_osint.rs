use std::env;
use std::time::Duration;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT, ACCEPT};
use regex::Regex;

struct SourceResult {
    source: String,
    subs: Vec<String>,
    error: Option<String>,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: subdomain_osint <domain>");
        std::process::exit(1);
    }

    let domain = args[1].trim().to_lowercase();

    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"));
    headers.insert(ACCEPT, HeaderValue::from_static("application/json, text/plain, */*"));

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .default_headers(headers)
        .pool_idle_timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(4)
        .build()
        .unwrap();

    type Fetcher = fn(&Client, &str) -> SourceResult;

    let fetchers: Vec<(&str, Fetcher)> = vec![
        ("crt.sh", fetch_crtsh as Fetcher),
        ("anubis", fetch_anubis as Fetcher),
        ("hackertarget", fetch_hackertarget as Fetcher),
        ("alienvault", fetch_alienvault as Fetcher),
        ("threatcrowd", fetch_threatcrowd as Fetcher),
        ("wayback", fetch_wayback as Fetcher),
        ("sonar", fetch_sonar as Fetcher),
        ("urlscan", fetch_urlscan as Fetcher),
        ("rapiddns", fetch_rapiddns as Fetcher),
        ("certspotter", fetch_certspotter as Fetcher),
        ("bufferover", fetch_bufferover as Fetcher),
        ("riddler", fetch_riddler as Fetcher),
        ("threatminer", fetch_threatminer as Fetcher),
        ("bevigil", fetch_bevigil as Fetcher),
        ("leakix", fetch_leakix as Fetcher),
        ("sublist3r", fetch_sublist3r as Fetcher),
        ("dnsdumpster", fetch_dnsdumpster as Fetcher),
    ];

    let total = fetchers.len();

    let client_ref = &client;
    let domain_ref = &domain;
    let results: Vec<SourceResult> = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for &(name, fetcher) in &fetchers {
            handles.push(scope.spawn(move || {
                let result = fetcher(client_ref, domain_ref);
                if let Some(err) = &result.error {
                    eprintln!("[osint] {} FAILED: {}", name, err);
                }
                for sub in &result.subs {
                    let out = serde_json::json!({
                        "subdomain": sub,
                        "source": result.source
                    });
                    println!("RESULT:{}", out);
                }
                result
            }));
        }
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    let mut all_subs: Vec<String> = results.into_iter()
        .flat_map(|r| r.subs)
        .collect();
    all_subs.sort();
    all_subs.dedup();

    let final_json = serde_json::json!({
        "domain": domain,
        "total": all_subs.len(),
        "sources_queried": total
    });
    println!("FINAL:{}", final_json);
}

fn clean_sub(sub: &str, domain: &str) -> Option<String> {
    let clean = sub.trim().trim_start_matches("*.").trim_start_matches("..")
        .trim_start_matches('.').to_lowercase();
    if clean.ends_with(domain) && clean.len() > domain.len() && !clean.contains(' ') {
        Some(clean)
    } else {
        None
    }
}

fn domain_regex(domain: &str) -> Regex {
    Regex::new(&format!(r"(?i)([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+{}", regex::escape(domain))).unwrap()
}

fn fetch_crtsh(client: &Client, domain: &str) -> SourceResult {
    let mut subs = Vec::new();
    let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
    match client.get(&url).send() {
        Ok(resp) => {
            if let Ok(json) = resp.json::<Vec<serde_json::Value>>() {
                for entry in json {
                    if let Some(name) = entry["name_value"].as_str() {
                        for sub in name.split('\n') {
                            if let Some(clean) = clean_sub(sub, domain) {
                                subs.push(clean);
                            }
                        }
                    }
                }
            }
        }
        Err(e) => return SourceResult { source: "crt.sh".into(), subs, error: Some(e.to_string()) },
    }
    subs.sort(); subs.dedup();
    SourceResult { source: "crt.sh".into(), subs, error: None }
}

fn fetch_anubis(client: &Client, domain: &str) -> SourceResult {
    let mut subs = Vec::new();
    let url = format!("https://jldc.me/anubis/subdomains/{}", domain);
    match client.get(&url).send() {
        Ok(resp) => {
            if let Ok(json) = resp.json::<Vec<String>>() {
                for sub in json {
                    if let Some(clean) = clean_sub(&sub, domain) {
                        subs.push(clean);
                    }
                }
            }
        }
        Err(e) => return SourceResult { source: "anubis".into(), subs, error: Some(e.to_string()) },
    }
    subs.sort(); subs.dedup();
    SourceResult { source: "anubis".into(), subs, error: None }
}

fn fetch_hackertarget(client: &Client, domain: &str) -> SourceResult {
    let mut subs = Vec::new();
    let url = format!("https://api.hackertarget.com/hostsearch/?q={}", domain);
    match client.get(&url).send() {
        Ok(resp) => {
            if let Ok(text) = resp.text() {
                for line in text.lines() {
                    if let Some(sub) = line.split(',').next() {
                        if let Some(clean) = clean_sub(sub, domain) {
                            subs.push(clean);
                        }
                    }
                }
            }
        }
        Err(e) => return SourceResult { source: "hackertarget".into(), subs, error: Some(e.to_string()) },
    }
    subs.sort(); subs.dedup();
    SourceResult { source: "hackertarget".into(), subs, error: None }
}

fn fetch_alienvault(client: &Client, domain: &str) -> SourceResult {
    let mut subs = Vec::new();
    let url = format!("https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns", domain);
    match client.get(&url).send() {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>() {
                if let Some(passive_dns) = json["passive_dns"].as_array() {
                    for entry in passive_dns {
                        if let Some(hostname) = entry["hostname"].as_str() {
                            if let Some(clean) = clean_sub(hostname, domain) {
                                subs.push(clean);
                            }
                        }
                    }
                }
            }
        }
        Err(e) => return SourceResult { source: "alienvault".into(), subs, error: Some(e.to_string()) },
    }
    subs.sort(); subs.dedup();
    SourceResult { source: "alienvault".into(), subs, error: None }
}

fn fetch_threatcrowd(client: &Client, domain: &str) -> SourceResult {
    let mut subs = Vec::new();
    let url = format!("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={}", domain);
    match client.get(&url).send() {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>() {
                if let Some(subdomains) = json["subdomains"].as_array() {
                    for s in subdomains {
                        if let Some(sub) = s.as_str() {
                            if let Some(clean) = clean_sub(sub, domain) {
                                subs.push(clean);
                            }
                        }
                    }
                }
            }
        }
        Err(e) => return SourceResult { source: "threatcrowd".into(), subs, error: Some(e.to_string()) },
    }
    subs.sort(); subs.dedup();
    SourceResult { source: "threatcrowd".into(), subs, error: None }
}

fn fetch_wayback(client: &Client, domain: &str) -> SourceResult {
    let mut subs = Vec::new();
    let url = format!("http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&fl=original&collapse=urlkey", domain);
    match client.get(&url).send() {
        Ok(resp) => {
            if let Ok(json) = resp.json::<Vec<Vec<String>>>() {
                for row in json.iter().skip(1) {
                    if !row.is_empty() {
                        let url_str = &row[0];
                        let clean = url_str.replace("http://", "").replace("https://", "");
                        let domain_part = clean.split('/').next().unwrap_or("").to_lowercase();
                        if domain_part.ends_with(domain) && domain_part.len() > domain.len() {
                            subs.push(domain_part);
                        }
                    }
                }
            }
        }
        Err(e) => return SourceResult { source: "wayback".into(), subs, error: Some(e.to_string()) },
    }
    subs.sort(); subs.dedup();
    SourceResult { source: "wayback".into(), subs, error: None }
}

fn fetch_sonar(client: &Client, domain: &str) -> SourceResult {
    let mut subs = Vec::new();
    let url = format!("https://sonar.omnisint.io/subdomains/{}", domain);
    match client.get(&url).send() {
        Ok(resp) => {
            if let Ok(json) = resp.json::<Vec<String>>() {
                for sub in json {
                    if let Some(clean) = clean_sub(&sub, domain) {
                        subs.push(clean);
                    }
                }
            }
        }
        Err(e) => return SourceResult { source: "sonar".into(), subs, error: Some(e.to_string()) },
    }
    subs.sort(); subs.dedup();
    SourceResult { source: "sonar".into(), subs, error: None }
}

fn fetch_urlscan(client: &Client, domain: &str) -> SourceResult {
    let mut subs = Vec::new();
    let url = format!("https://urlscan.io/api/v1/search/?q=domain:{}&size=100", domain);
    match client.get(&url).send() {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>() {
                if let Some(results) = json["results"].as_array() {
                    for r in results {
                        if let Some(sub) = r["page"]["domain"].as_str() {
                            if let Some(clean) = clean_sub(sub, domain) {
                                subs.push(clean);
                            }
                        }
                    }
                }
            }
        }
        Err(e) => return SourceResult { source: "urlscan".into(), subs, error: Some(e.to_string()) },
    }
    subs.sort(); subs.dedup();
    SourceResult { source: "urlscan".into(), subs, error: None }
}

fn fetch_rapiddns(client: &Client, domain: &str) -> SourceResult {
    let mut subs = Vec::new();
    let url = format!("https://rapiddns.io/subdomain/{}?full=1", domain);
    match client.get(&url).send() {
        Ok(resp) => {
            if let Ok(text) = resp.text() {
                let re = domain_regex(domain);
                for cap in re.captures_iter(&text) {
                    let s = cap[0].to_lowercase().trim_start_matches(".").to_string();
                    if s.ends_with(domain) && s.len() > domain.len() {
                        subs.push(s);
                    }
                }
            }
        }
        Err(e) => return SourceResult { source: "rapiddns".into(), subs, error: Some(e.to_string()) },
    }
    subs.sort(); subs.dedup();
    SourceResult { source: "rapiddns".into(), subs, error: None }
}

fn fetch_certspotter(client: &Client, domain: &str) -> SourceResult {
    let mut subs = Vec::new();
    let url = format!("https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names", domain);
    match client.get(&url).send() {
        Ok(resp) => {
            if let Ok(json) = resp.json::<Vec<serde_json::Value>>() {
                for entry in json {
                    if let Some(dns_names) = entry["dns_names"].as_array() {
                        for name in dns_names {
                            if let Some(n) = name.as_str() {
                                if let Some(clean) = clean_sub(n, domain) {
                                    subs.push(clean);
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(e) => return SourceResult { source: "certspotter".into(), subs, error: Some(e.to_string()) },
    }
    subs.sort(); subs.dedup();
    SourceResult { source: "certspotter".into(), subs, error: None }
}

fn fetch_bufferover(client: &Client, domain: &str) -> SourceResult {
    let mut subs = Vec::new();
    let url = format!("https://dns.bufferover.run/dns?q=.{}", domain);
    match client.get(&url).send() {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>() {
                if let Some(fdns) = json["FDNS_A"].as_array() {
                    for entry in fdns {
                        if let Some(s) = entry.as_str() {
                            if let Some(sub) = s.split(',').nth(1) {
                                if let Some(clean) = clean_sub(sub, domain) {
                                    subs.push(clean);
                                }
                            }
                        }
                    }
                }
                if let Some(rdns) = json["RDNS"].as_array() {
                    for entry in rdns {
                        if let Some(s) = entry.as_str() {
                            if let Some(sub) = s.split(',').nth(1) {
                                if let Some(clean) = clean_sub(sub, domain) {
                                    subs.push(clean);
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(e) => return SourceResult { source: "bufferover".into(), subs, error: Some(e.to_string()) },
    }
    subs.sort(); subs.dedup();
    SourceResult { source: "bufferover".into(), subs, error: None }
}

fn fetch_riddler(client: &Client, domain: &str) -> SourceResult {
    let mut subs = Vec::new();
    let url = format!("https://riddler.io/search/exportcsv?q=pld:{}", domain);
    match client.get(&url).send() {
        Ok(resp) => {
            if let Ok(text) = resp.text() {
                for line in text.lines().skip(1) {
                    if let Some(sub) = line.split(',').nth(4) {
                        let clean = sub.trim_matches('"').to_lowercase();
                        if clean.ends_with(domain) && clean.len() > domain.len() {
                            subs.push(clean);
                        }
                    }
                }
            }
        }
        Err(e) => return SourceResult { source: "riddler".into(), subs, error: Some(e.to_string()) },
    }
    subs.sort(); subs.dedup();
    SourceResult { source: "riddler".into(), subs, error: None }
}

fn fetch_threatminer(client: &Client, domain: &str) -> SourceResult {
    let mut subs = Vec::new();
    let url = format!("https://api.threatminer.org/v2/domain.php?q={}&rt=5", domain);
    match client.get(&url).send() {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>() {
                if let Some(results) = json["results"].as_array() {
                    for r in results {
                        if let Some(s) = r.as_str() {
                            if let Some(clean) = clean_sub(s, domain) {
                                subs.push(clean);
                            }
                        }
                    }
                }
            }
        }
        Err(e) => return SourceResult { source: "threatminer".into(), subs, error: Some(e.to_string()) },
    }
    subs.sort(); subs.dedup();
    SourceResult { source: "threatminer".into(), subs, error: None }
}

fn fetch_bevigil(client: &Client, domain: &str) -> SourceResult {
    let mut subs = Vec::new();
    let url = format!("https://osint.bevigil.com/api/{}/subdomains/", domain);
    match client.get(&url).send() {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>() {
                if let Some(subdomains) = json["subdomains"].as_array() {
                    for sub in subdomains {
                        if let Some(s) = sub.as_str() {
                            if let Some(clean) = clean_sub(s, domain) {
                                subs.push(clean);
                            }
                        }
                    }
                }
            }
        }
        Err(e) => return SourceResult { source: "bevigil".into(), subs, error: Some(e.to_string()) },
    }
    subs.sort(); subs.dedup();
    SourceResult { source: "bevigil".into(), subs, error: None }
}

fn fetch_leakix(_client: &Client, domain: &str) -> SourceResult {
    let mut subs = Vec::new();
    let url = format!("https://leakix.net/api/subdomains/{}", domain);
    let mut leakix_headers = HeaderMap::new();
    leakix_headers.insert("Accept", HeaderValue::from_static("application/json"));
    let leakix_client = Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .default_headers(leakix_headers)
        .build().unwrap();
    match leakix_client.get(&url).send() {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>() {
                if let Some(entries) = json.as_array() {
                    for entry in entries {
                        if let Some(sub) = entry["subdomain"].as_str().or_else(|| entry["domain"].as_str()) {
                            if let Some(clean) = clean_sub(sub, domain) {
                                subs.push(clean);
                            }
                        }
                    }
                }
            }
        }
        Err(e) => return SourceResult { source: "leakix".into(), subs, error: Some(e.to_string()) },
    }
    subs.sort(); subs.dedup();
    SourceResult { source: "leakix".into(), subs, error: None }
}

fn fetch_sublist3r(client: &Client, domain: &str) -> SourceResult {
    let mut subs = Vec::new();
    let url = format!("https://api.sublist3r.com/search.php?domain={}", domain);
    match client.get(&url).send() {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>() {
                if let Some(subdomains) = json["subdomains"].as_array() {
                    for sub in subdomains {
                        if let Some(s) = sub.as_str() {
                            if let Some(clean) = clean_sub(s, domain) {
                                subs.push(clean);
                            }
                        }
                    }
                }
            }
        }
        Err(e) => return SourceResult { source: "sublist3r".into(), subs, error: Some(e.to_string()) },
    }
    subs.sort(); subs.dedup();
    SourceResult { source: "sublist3r".into(), subs, error: None }
}

fn fetch_dnsdumpster(client: &Client, domain: &str) -> SourceResult {
    let mut subs = Vec::new();
    let csrf_re = Regex::new(r#"name="csrfmiddlewaretoken" value="([^"]+)"#).unwrap();
    match client.get("https://dnsdumpster.com/").send() {
        Ok(resp) => {
            let set_cookie = resp.headers().get("set-cookie")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let cookies = set_cookie.split(';')
                .map(|s| s.trim())
                .filter(|s| s.contains('='))
                .collect::<Vec<_>>()
                .join("; ");
            if let Ok(html) = resp.text() {
                let csrf = csrf_re.captures(&html)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str())
                    .unwrap_or("");
                let body = format!("csrfmiddlewaretoken={}&targeturi={}", csrf, domain);
                let mut post_headers = HeaderMap::new();
                post_headers.insert("Content-Type", HeaderValue::from_static("application/x-www-form-urlencoded"));
                post_headers.insert("Referer", HeaderValue::from_static("https://dnsdumpster.com/"));
                if !cookies.is_empty() {
                    if let Ok(cv) = HeaderValue::from_str(&cookies) {
                        post_headers.insert("Cookie", cv);
                    }
                }
                if let Ok(post_resp) = client.post("https://dnsdumpster.com/")
                    .headers(post_headers)
                    .body(body)
                    .send()
                {
                    if let Ok(html) = post_resp.text() {
                        let re = domain_regex(domain);
                        for cap in re.captures_iter(&html) {
                            let s = cap[0].to_lowercase().trim_start_matches(".").to_string();
                            if s.ends_with(domain) && s.len() > domain.len() {
                                subs.push(s);
                            }
                        }
                    }
                }
            }
        }
        Err(e) => return SourceResult { source: "dnsdumpster".into(), subs, error: Some(e.to_string()) },
    }
    subs.sort(); subs.dedup();
    SourceResult { source: "dnsdumpster".into(), subs, error: None }
}
