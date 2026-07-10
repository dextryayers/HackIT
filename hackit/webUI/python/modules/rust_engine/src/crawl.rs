use crate::common::{CrawlResult, build_client};

pub async fn crawl_website(url: &str) -> CrawlResult {
    let full_url = if url.starts_with("http") { url.to_string() } else { format!("https://{}", url) };
    let mut result = CrawlResult { url: full_url.clone(), title: None, links: vec![], meta: vec![], status: None };
    let client = match build_client(15) { Some(c) => c, None => return result };
    if let Ok(resp) = client.get(&full_url).send().await {
        result.status = Some(resp.status().as_u16());
        if let Ok(body) = resp.text().await {
            let lower = body.to_lowercase();
            if let Some(start) = lower.find("<title") {
                if let Some(title_start) = lower[start..].find('>') {
                    if let Some(title_end) = lower[start+title_start+1..].find("</title") {
                        result.title = Some(body[start+title_start+1..start+title_start+1+title_end].trim().to_string());
                    }
                }
            }
            let mut pos = 0;
            while let Some(meta_start) = lower[pos..].find("<meta") {
                if let Some(meta_end) = lower[pos+meta_start..].find('>') {
                    let meta_tag = &body[pos+meta_start..pos+meta_start+meta_end+1];
                    let mut name = String::new(); let mut content = String::new();
                    if let Some(n) = meta_tag.find("name=\"") { let rest = &meta_tag[n+6..]; name = rest.split('"').next().unwrap_or("").to_string(); }
                    else if let Some(n) = meta_tag.find("name='") { let rest = &meta_tag[n+5..]; name = rest.split('\'').next().unwrap_or("").to_string(); }
                    else if let Some(n) = meta_tag.find("property=\"") { let rest = &meta_tag[n+9..]; name = rest.split('"').next().unwrap_or("").to_string(); }
                    if let Some(c) = meta_tag.find("content=\"") { let rest = &meta_tag[c+8..]; content = rest.split('"').next().unwrap_or("").to_string(); }
                    if !name.is_empty() { result.meta.push((name, content)); }
                    pos += meta_start + meta_end + 1;
                } else { break; }
            }
            pos = 0;
            while let Some(href_start) = lower[pos..].find("href=\"") {
                let rest = &body[pos+href_start+6..];
                let link: String = rest.split('"').next().unwrap_or("").chars().filter(|&c| c != '\n' && c != '\r').collect();
                if link.starts_with("http") || link.starts_with('/') || link.starts_with(".") {
                    if link.len() > 3 && link.len() < 500 && !result.links.contains(&link) { result.links.push(link); }
                }
                pos += href_start + 6;
            }
        }
    }
    result.links.sort(); result.links.dedup(); result.links.truncate(200);
    result
}
