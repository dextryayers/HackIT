use crate::common::*;
use crate::{progress, progress_done};
use regex::Regex;

pub async fn analyze(url: &str) -> WebPerformanceResult {
    progress!("web_performance", "running");
    let mut result = WebPerformanceResult { url: url.to_string(), ..Default::default() };
    let url = normalize_url(url);

    if let Some(client) = build_client(15) {
        let start = std::time::Instant::now();
        match client.get(&url).send().await {
            Ok(resp) => {
                let first_byte = start.elapsed().as_millis() as u64;
                result.first_byte_time_ms = first_byte;
                let status = resp.status();

                let total_size = resp
                    .headers()
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                result.total_size_bytes = total_size;

                let mut resource_sizes = Vec::new();

                if let Ok(html) = resp.text().await {
                    let load_time = start.elapsed().as_millis() as u64;
                    result.load_time_ms = load_time;

                    let script_re = Regex::new(r#"<script[^>]+src=["']([^"']+)["']"#).unwrap();
                    let css_re = Regex::new(r#"<link[^>]+href=["']([^"']+)["'][^>]*rel=["']stylesheet["']"#).unwrap();
                    let img_re = Regex::new(r#"<img[^>]+src=["']([^"']+)["']"#).unwrap();

                    let mut resource_urls: Vec<(String, String)> = Vec::new();

                    for cap in script_re.captures_iter(&html) {
                        resource_urls.push((cap[1].to_string(), "script".to_string()));
                    }
                    for cap in css_re.captures_iter(&html) {
                        resource_urls.push((cap[1].to_string(), "stylesheet".to_string()));
                    }
                    for cap in img_re.captures_iter(&html) {
                        resource_urls.push((cap[1].to_string(), "image".to_string()));
                    }

                    let mut request_count = 1u32;
                    let mut total_measured = total_size;

                    for (res_url, res_type) in resource_urls.into_iter().take(30) {
                        let abs_url = if res_url.starts_with("http") {
                            res_url
                        } else {
                            format!("{}/{}", url.trim_end_matches('/'), res_url.trim_start_matches('/'))
                        };

                        if let Ok(res_resp) = client.get(&abs_url).send().await {
                            request_count += 1;
                            let res_size = res_resp
                                .headers()
                                .get("content-length")
                                .and_then(|v| v.to_str().ok())
                                .and_then(|v| v.parse::<u64>().ok())
                                .unwrap_or(0);
                            total_measured = total_measured.saturating_add(res_size);
                            resource_sizes.push(ResourceSize {
                                url: abs_url,
                                size_bytes: res_size,
                                resource_type: res_type,
                            });
                        }
                    }

                    result.request_count = request_count;
                    if total_measured > 0 {
                        result.total_size_bytes = total_measured;
                    }
                    result.resource_sizes = resource_sizes.clone();

                    let mut score = 0u32;

                    score += if load_time < 1000 {
                        40
                    } else if load_time < 3000 {
                        25
                    } else if load_time < 5000 {
                        10
                    } else {
                        0
                    };

                    let total_mb = result.total_size_bytes / (1024 * 1024);
                    score += if total_mb < 1 {
                        30
                    } else if total_mb < 3 {
                        15
                    } else if total_mb < 5 {
                        5
                    } else {
                        0
                    };

                    score += if request_count < 20 {
                        30
                    } else if request_count < 50 {
                        15
                    } else if request_count < 100 {
                        5
                    } else {
                        0
                    };

                    result.performance_score = score.min(100);

                    let mut suggestions = Vec::new();
                    if load_time >= 1000 {
                        suggestions.push("Slow page load time - consider optimizing server response and using caching".to_string());
                    }
                    if total_mb >= 1 {
                        suggestions.push(format!("Large page size ({}MB) - compress assets and lazy-load content", total_mb));
                    }
                    if request_count > 20 {
                        suggestions.push(format!("High request count ({}) - combine resources and reduce HTTP requests", request_count));
                    }
                    let large_images: Vec<&ResourceSize> = resource_sizes.iter().filter(|r| r.resource_type == "image" && r.size_bytes > 500_000).collect();
                    if !large_images.is_empty() {
                        suggestions.push(format!("{} large image(s) over 500KB - optimize images for faster loading", large_images.len()));
                    }
                    if status.is_redirection() {
                        suggestions.push("Page uses redirects - minimize redirect chains for faster load times".to_string());
                    }
                    if result.first_byte_time_ms > 500 {
                        suggestions.push("High time-to-first-byte - improve server response time and use CDN".to_string());
                    }
                    result.suggestions = suggestions;
                } else {
                    result.error = Some("Failed to parse response body".to_string());
                }
            }
            Err(e) => {
                result.error = Some(format!("{:.100}", e));
            }
        }
    } else {
        result.error = Some("Failed to create HTTP client".to_string());
    }

    progress_done!("web_performance");
    result
}


