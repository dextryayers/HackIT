use crate::common::*;
use std::time::Duration;

const DEEP_LINK_PATHS: &[&str] = &[
    ".well-known/apple-app-site-association",
    ".well-known/assetlinks.json",
];

const MOBILE_SDK_KEYWORDS: &[(&str, &[&str])] = &[
    ("Firebase", &["firebase"]),
    ("OneSignal", &["onesignal"]),
    ("Branch.io", &["branch.io"]),
    ("Adjust", &["adjust.com"]),
    ("Flutter", &["flutter.js", "flutter_service_worker"]),
    ("React Native", &["react-native"]),
];

const MOBILE_API_PATHS: &[&str] = &[
    "api/mobile",
    "api/v1/mobile",
    "mobile-api",
    "graphql",
];

const MOBILE_CONFIG_PATHS: &[&str] = &[
    "google-services.json",
    "GoogleService-Info.plist",
    "app-config.json",
];

fn extract_domain(target: &str) -> String {
    let cleaned = target
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(target);
    cleaned.to_string()
}

fn normalize_url(target: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!("https://{}", target)
    }
}

async fn check_url(client: &reqwest::Client, url: &str) -> Option<u16> {
    match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if status < 400 || status == 403 {
                Some(status)
            } else {
                None
            }
        }
        _ => None,
    }
}

async fn check_deep_links(client: &reqwest::Client, base_url: &str) -> Vec<String> {
    let mut found = Vec::new();
    for path in DEEP_LINK_PATHS {
        let url = format!("{}/{}", base_url.trim_end_matches('/'), path);
        if let Some(status) = check_url(client, &url).await {
            found.push(format!("{} (HTTP {})", url, status));
        }
    }
    found
}

async fn check_mobile_sdks(client: &reqwest::Client, base_url: &str) -> Vec<String> {
    let mut sdk_usage = Vec::new();
    let url = base_url.trim_end_matches('/').to_string();
    let body = match client.get(&url).send().await {
        Ok(resp) => resp.text().await.unwrap_or_default(),
        _ => return sdk_usage,
    };
    let body_lower = body.to_lowercase();
    for (sdk_name, keywords) in MOBILE_SDK_KEYWORDS {
        for kw in *keywords {
            if body_lower.contains(kw) {
                sdk_usage.push(sdk_name.to_string());
                break;
            }
        }
    }
    sdk_usage
}

async fn check_mobile_api_endpoints(client: &reqwest::Client, base_url: &str) -> Vec<String> {
    let mut endpoints = Vec::new();
    let base = base_url.trim_end_matches('/');
    for path in MOBILE_API_PATHS {
        let url = format!("{}/{}", base, path);
        if let Some(status) = check_url(client, &url).await {
            endpoints.push(format!("{} (HTTP {})", url, status));
        }
    }
    endpoints
}

async fn check_app_store_presence(target: &str) -> Vec<MobilePlatform> {
    let mut platforms = Vec::new();
    let domain = extract_domain(target);
    let main_part = domain.split('.').next().unwrap_or(&domain);

    let bundle_id = format!("com.{}", main_part);

    let ios_url = format!("https://itunes.apple.com/lookup?bundleId={}", bundle_id);
    let android_url = format!(
        "https://play.google.com/store/apps/details?id={}",
        bundle_id
    );

    let store_client = match build_client(10) {
        Some(c) => c,
        None => return platforms,
    };

    let ios_resp = store_client
        .get(&ios_url)
        .timeout(Duration::from_secs(10))
        .send()
        .await;
    if let Ok(resp) = ios_resp {
        if resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            if text.contains("\"resultCount\":1") || text.contains(&bundle_id) {
                platforms.push(MobilePlatform {
                    platform: "iOS".into(),
                    app_id: bundle_id.clone(),
                    store_url: Some(format!(
                        "https://apps.apple.com/app/id?bundleId={}",
                        bundle_id
                    )),
                    detected_from: "app_store_lookup".into(),
                });
            }
        }
    }

    let android_resp = store_client
        .get(&android_url)
        .timeout(Duration::from_secs(10))
        .send()
        .await;
    if let Ok(resp) = android_resp {
        if resp.status().is_success() {
            platforms.push(MobilePlatform {
                platform: "Android".into(),
                app_id: bundle_id.clone(),
                store_url: Some(android_url),
                detected_from: "play_store_lookup".into(),
            });
        }
    }

    platforms
}

async fn check_mobile_config_files(client: &reqwest::Client, base_url: &str) -> Vec<String> {
    let mut configs = Vec::new();
    let base = base_url.trim_end_matches('/');
    for path in MOBILE_CONFIG_PATHS {
        let url = format!("{}/{}", base, path);
        if let Some(status) = check_url(client, &url).await {
            configs.push(format!("{} (HTTP {})", url, status));
        }
    }
    configs
}

pub async fn scan(target: &str) -> MobileAppScanResult {
    let base_url = normalize_url(target);

    let client = match build_client(15) {
        Some(c) => c,
        None => {
            return MobileAppScanResult {
                target: target.to_string(),
                has_mobile_apps: false,
                platforms: Vec::new(),
                api_endpoints: Vec::new(),
                deep_links: Vec::new(),
                sdk_usage: Vec::new(),
                error: Some("Failed to build HTTP client".into()),
            };
        }
    };

    let deep_links = check_deep_links(&client, &base_url).await;
    let sdk_usage = check_mobile_sdks(&client, &base_url).await;
    let api_endpoints = check_mobile_api_endpoints(&client, &base_url).await;
    let platforms = check_app_store_presence(target).await;
    let config_files = check_mobile_config_files(&client, &base_url).await;

    let mut all_api_endpoints = api_endpoints;
    all_api_endpoints.extend(config_files);

    let has_mobile_apps = !platforms.is_empty()
        || !deep_links.is_empty()
        || !sdk_usage.is_empty()
        || !all_api_endpoints.is_empty();

    MobileAppScanResult {
        target: target.to_string(),
        has_mobile_apps,
        platforms,
        api_endpoints: all_api_endpoints,
        deep_links,
        sdk_usage,
        error: None,
    }
}
