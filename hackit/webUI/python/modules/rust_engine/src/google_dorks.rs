use crate::common::{ScanConfig, build_client};
use crate::common::{GoogleDorkResult, DorkResult};
use std::time::Duration;
use tokio::task;

const DORK_TEMPLATES: &[(&str, &str)] = &[
    ("site_index", "site:{domain} index of"),
    ("site_login", "site:{domain} login"),
    ("site_admin", "site:{domain} admin"),
    ("site_backup", "site:{domain} backup"),
    ("site_config", "site:{domain} config"),
    ("site_database", "site:{domain} database"),
    ("site_sql", "site:{domain} sql"),
    ("site_error", "site:{domain} error"),
    ("site_debug", "site:{domain} debug"),
    ("site_api", "site:{domain} api"),
    ("site_docs", "site:{domain} docs"),
    ("site_swagger", "site:{domain} swagger"),
    ("site_graphql", "site:{domain} graphql"),
    ("site_robots", "site:{domain} robots.txt"),
    ("site_sitemap", "site:{domain} sitemap.xml"),
    ("site_env", "site:{domain} .env"),
    ("site_git", "site:{domain} .git"),
    ("site_svn", "site:{domain} .svn"),
    ("filetype_pdf", "site:{domain} filetype:pdf"),
    ("filetype_doc", "site:{domain} filetype:doc"),
    ("filetype_xls", "site:{domain} filetype:xls"),
    ("filetype_csv", "site:{domain} filetype:csv"),
    ("filetype_sql", "site:{domain} filetype:sql"),
    ("filetype_log", "site:{domain} filetype:log"),
    ("filetype_conf", "site:{domain} filetype:conf"),
    ("filetype_ini", "site:{domain} filetype:ini"),
    ("filetype_xml", "site:{domain} filetype:xml"),
    ("filetype_json", "site:{domain} filetype:json"),
    ("intitle_index", "intitle:\"index of\" {domain}"),
    ("intitle_login", "intitle:\"login\" site:{domain}"),
    ("intitle_admin", "intitle:\"admin\" site:{domain}"),
    ("inurl_admin", "inurl:admin site:{domain}"),
    ("inurl_login", "inurl:login site:{domain}"),
    ("inurl_api", "inurl:api site:{domain}"),
    ("inurl_debug", "inurl:debug site:{domain}"),
    ("inurl_config", "inurl:config site:{domain}"),
    ("inurl_backup", "inurl:backup site:{domain}"),
    ("inurl_test", "inurl:test site:{domain}"),
    ("inurl_staging", "inurl:staging site:{domain}"),
    ("email_domain", "\"@{domain}\""),
    ("password_domain", "password site:{domain}"),
    ("username_domain", "username site:{domain}"),
    ("credential_domain", "credential site:{domain}"),
    ("confidential", "confidential site:{domain}"),
    ("internal", "internal site:{domain}"),
    ("private", "private site:{domain}"),
    ("restricted", "restricted site:{domain}"),
];

const SEARCH_ENGINES: &[(&str, &str)] = &[
    ("Bing", "https://www.bing.com/search?q={query}&count=20"),
    ("DuckDuckGo", "https://html.duckduckgo.com/html/?q={query}"),
    ("Yandex", "https://yandex.com/search/?text={query}"),
    ("Baidu", "https://www.baidu.com/s?wd={query}"),
    ("Mojeek", "https://www.mojeek.com/search?q={query}"),
];

pub async fn scan(target: &str, _config: &ScanConfig) -> GoogleDorkResult {
    let client = build_client(15).unwrap_or_default();
    let domain = target.trim().to_lowercase();
    let timeout = Duration::from_secs(10);
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(15));
    let mut handles = Vec::new();

    for &(template_name, template) in DORK_TEMPLATES {
        let query = template.replace("{domain}", &domain);
        for &(engine_name, engine_url) in SEARCH_ENGINES {
            let url = engine_url.replace("{query}", &query);
            let client = client.clone();
            let sem = sem.clone();
            let template_name = template_name.to_string();
            let engine_name = engine_name.to_string();
            let query = query.clone();
            let domain_clone = domain.clone();
            handles.push(task::spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                let resp = client.get(&url).timeout(timeout).send().await.ok()?;
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let results_found = count_results(&body, &domain_clone);
                if status == 200 && results_found > 0 {
                    Some(DorkResult {
                        dork_name: template_name,
                        query: query.clone(),
                        engine: engine_name,
                        results: results_found,
                        snippet: body.chars().take(300).collect(),
                    })
                } else {
                    None
                }
            }));
        }
    }

    let mut dork_results = Vec::new();
    let mut total_results = 0;
    let mut unique_dorks = std::collections::HashSet::new();

    for h in handles {
        if let Ok(Some(r)) = h.await {
            total_results += r.results;
            unique_dorks.insert(r.dork_name.clone());
            dork_results.push(r);
        }
    }

    dork_results.sort_by(|a, b| b.results.cmp(&a.results));

    GoogleDorkResult {
        domain,
        total_dorks_executed: DORK_TEMPLATES.len() * SEARCH_ENGINES.len(),
        dorks_with_results: dork_results.len(),
        total_results,
        unique_dorks_found: unique_dorks.len(),
        results: dork_results.into_iter().take(100).collect(),
    }
}

fn count_results(body: &str, domain: &str) -> usize {
    let lower = body.to_lowercase();
    let domain_lower = domain.to_lowercase();
    lower.matches(&domain_lower).count()
}
