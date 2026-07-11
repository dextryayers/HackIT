use crate::common::{CloudResult, CloudProvider, CloudBucket, build_client, normalize_url};

pub async fn detect(target: &str) -> CloudResult {
    let url = normalize_url(target);
    let client = build_client(15);
    let mut providers = Vec::new();
    let mut buckets = Vec::new();
    let domain = url.replace("https://", "").replace("http://", "").split('/').next().unwrap_or("").to_string();

    if let Some(client) = client {
        check_aws(&client, &url, &domain, &mut providers, &mut buckets).await;
        check_azure(&client, &url, &domain, &mut providers).await;
        check_gcp(&client, &url, &domain, &mut providers).await;
        check_cloudflare(&client, &url, &mut providers).await;
        check_github_pages(&domain, &mut providers);
        check_heroku(&domain, &mut providers);
        check_vercel(&domain, &mut providers);
        check_netlify(&domain, &mut providers);
        check_fastly(&client, &url, &mut providers).await;
        check_akamai(&client, &url, &mut providers).await;

        discover_buckets(&client, &domain, &mut buckets).await;
    }

    CloudResult { target: target.to_string(), providers, buckets }
}

async fn check_aws(client: &reqwest::Client, url: &str, domain: &str, providers: &mut Vec<CloudProvider>, buckets: &mut Vec<CloudBucket>) {
    let mut services = Vec::new();
    let mut confidence = "Low";

    if domain.ends_with("amazonaws.com") || domain.ends_with("compute.amazonaws.com") {
        services.push("EC2".into()); confidence = "High";
    }
    if domain.ends_with("s3.amazonaws.com") || domain.contains("s3-") || domain.contains("s3.") {
        services.push("S3".into()); confidence = "High";
    }
    if domain.ends_with("cloudfront.net") {
        services.push("CloudFront".into()); confidence = "High";
    }
    if domain.ends_with("elb.amazonaws.com") || domain.contains("elb-") {
        services.push("ELB".into()); confidence = "High";
    }

    if let Ok(resp) = client.get(url).send().await {
        for (name, _) in resp.headers().iter() {
            let n = name.as_str().to_lowercase();
            if n.starts_with("x-amz-") {
                services.push(format!("AWS-{}", n));
                confidence = "High";
            }
        }
        if let Some(v) = resp.headers().get("server").and_then(|v| v.to_str().ok()) {
            if v.contains("CloudFront") { services.push("CloudFront".into()); confidence = "High"; }
            if v.contains("AmazonS3") { services.push("S3".into()); confidence = "High"; }
        }
    }

    // Check common S3 buckets
    let bucket_names = vec![domain.replace('.', "-"), domain.split('.').next().unwrap_or("").to_string()];
    for bname in &bucket_names {
        let bucket_url = format!("https://{}.s3.amazonaws.com", bname);
        if let Ok(resp) = client.get(&bucket_url).send().await {
            let exists = resp.status().is_success() || resp.status().as_u16() == 403;
            let accessible = resp.status().is_success();
            buckets.push(CloudBucket { url: bucket_url, provider: "AWS S3".into(), exists, accessible });
        }
    }

    if !services.is_empty() {
        providers.push(CloudProvider { name: "Amazon Web Services".into(), services, confidence: confidence.into() });
    }
}

async fn check_azure(client: &reqwest::Client, url: &str, domain: &str, providers: &mut Vec<CloudProvider>) {
    let mut services = Vec::new();
    if domain.ends_with("azurewebsites.net") { services.push("App Service".into()); }
    if domain.ends_with("azureedge.net") || domain.ends_with("azurefd.net") { services.push("CDN/Front Door".into()); }
    if domain.ends_with("blob.core.windows.net") { services.push("Blob Storage".into()); }

    if let Ok(resp) = client.get(url).send().await {
        for (name, _) in resp.headers().iter() {
            let n = name.as_str().to_lowercase();
            if n.starts_with("x-ms-") || n.starts_with("x-azure-") {
                services.push(format!("Azure-{}", n));
            }
        }
        if let Some(v) = resp.headers().get("server").and_then(|v| v.to_str().ok()) {
            if v.contains("Azure") { services.push("Azure".into()); }
        }
    }

    if !services.is_empty() {
        providers.push(CloudProvider { name: "Microsoft Azure".into(), services, confidence: "High".into() });
    }
}

async fn check_gcp(client: &reqwest::Client, url: &str, domain: &str, providers: &mut Vec<CloudProvider>) {
    let mut services = Vec::new();
    if domain.ends_with("appspot.com") { services.push("App Engine".into()); }
    if domain.ends_with("cloudfunctions.net") { services.push("Cloud Functions".into()); }
    if domain.ends_with("compute.googleapis.com") { services.push("Compute Engine".into()); }
    if domain.contains("storage.googleapis.com") || domain.ends_with("storage.googleapis.com") { services.push("Cloud Storage".into()); }
    if domain.ends_with("run.app") { services.push("Cloud Run".into()); }

    if let Ok(resp) = client.get(url).send().await {
        for (name, _) in resp.headers().iter() {
            let n = name.as_str().to_lowercase();
            if n.starts_with("x-goog-") {
                services.push(format!("GCP-{}", n));
            }
        }
    }

    if !services.is_empty() {
        providers.push(CloudProvider { name: "Google Cloud Platform".into(), services, confidence: "High".into() });
    }
}

async fn check_cloudflare(client: &reqwest::Client, url: &str, providers: &mut Vec<CloudProvider>) {
    let mut services = Vec::new();
    if let Ok(resp) = client.get(url).send().await {
        let has_cf = resp.headers().get("cf-ray").is_some()
            || resp.headers().get("cf-cache-status").is_some()
            || resp.headers().get("cf-request-id").is_some()
            || resp.headers().get("server").and_then(|v| v.to_str().ok()).map(|s| s.contains("cloudflare")).unwrap_or(false);
        if has_cf {
            services.push("CDN".into());
            services.push("DDoS Protection".into());
            services.push("SSL/TLS".into());
            providers.push(CloudProvider { name: "Cloudflare".into(), services, confidence: "High".into() });
        }
    }
}

fn check_github_pages(domain: &str, providers: &mut Vec<CloudProvider>) {
    if domain.ends_with("github.io") {
        providers.push(CloudProvider {
            name: "GitHub Pages".into(),
            services: vec!["Static Hosting".into()],
            confidence: "High".into(),
        });
    }
}

fn check_heroku(domain: &str, providers: &mut Vec<CloudProvider>) {
    if domain.ends_with("herokuapp.com") || domain.ends_with("herokudns.com") {
        providers.push(CloudProvider {
            name: "Heroku".into(),
            services: vec!["PaaS".into()],
            confidence: "High".into(),
        });
    }
}

fn check_vercel(domain: &str, providers: &mut Vec<CloudProvider>) {
    if domain.ends_with("vercel.app") || domain.ends_with("now.sh") {
        providers.push(CloudProvider {
            name: "Vercel".into(),
            services: vec!["Edge Functions".into(), "Static Hosting".into()],
            confidence: "High".into(),
        });
    }
}

fn check_netlify(domain: &str, providers: &mut Vec<CloudProvider>) {
    if domain.ends_with("netlify.app") || domain.contains("netlify") {
        providers.push(CloudProvider {
            name: "Netlify".into(),
            services: vec!["Static Hosting".into(), "Edge Functions".into()],
            confidence: "High".into(),
        });
    }
}

async fn check_fastly(client: &reqwest::Client, url: &str, providers: &mut Vec<CloudProvider>) {
    if let Ok(resp) = client.get(url).send().await {
        if resp.headers().get("x-fastly-request-id").is_some()
            || resp.headers().get("x-served-by").and_then(|v| v.to_str().ok()).map(|s| s.contains("cache")).unwrap_or(false)
            || resp.headers().get("x-cache").is_some()
        {
            providers.push(CloudProvider {
                name: "Fastly".into(),
                services: vec!["CDN".into()],
                confidence: "High".into(),
            });
        }
    }
}

async fn check_akamai(client: &reqwest::Client, url: &str, providers: &mut Vec<CloudProvider>) {
    if let Ok(resp) = client.get(url).send().await {
        if resp.headers().get("x-akamai-transformed").is_some()
            || resp.headers().get("x-akamai-request-id").is_some()
        {
            providers.push(CloudProvider {
                name: "Akamai".into(),
                services: vec!["CDN".into()],
                confidence: "High".into(),
            });
        }
    }
}

async fn discover_buckets(client: &reqwest::Client, domain: &str, buckets: &mut Vec<CloudBucket>) {
    let domain_parts: Vec<&str> = domain.split('.').collect();
    let base = domain_parts.get(0).copied().unwrap_or("");

    let candidates = vec![
        format!("https://{}-backup.s3.amazonaws.com", base),
        format!("https://{}-dev.s3.amazonaws.com", base),
        format!("https://{}-assets.s3.amazonaws.com", base),
        format!("https://{}-data.s3.amazonaws.com", base),
        format!("https://{}-uploads.s3.amazonaws.com", base),
        format!("https://{}-public.s3.amazonaws.com", base),
        format!("https://{}-static.s3.amazonaws.com", base),
        format!("https://{}-media.s3.amazonaws.com", base),
        format!("https://{}-files.s3.amazonaws.com", base),
        format!("https://{}-backup.s3.us-east-1.amazonaws.com", base),
        format!("https://{}.storage.googleapis.com", base),
        format!("https://{}-storage.googleapis.com", base),
        format!("https://{}.blob.core.windows.net", base),
        format!("https://{}-blob.core.windows.net", base),
        format!("https://{}.s3.amazonaws.com", domain),
        format!("https://{}.digitaloceanspaces.com", base),
        format!("https://{}.linodeobjects.com", base),
    ];

    for url in &candidates {
        if let Ok(resp) = client.get(url).send().await {
            let status = resp.status().as_u16();
            let exists = status < 500;
            let accessible = status < 400;
            if exists {
                let provider = if url.contains("s3.amazonaws.com") { "AWS S3" }
                    else if url.contains("storage.googleapis.com") { "GCP Cloud Storage" }
                    else if url.contains("blob.core.windows.net") { "Azure Blob" }
                    else if url.contains("digitaloceanspaces.com") { "DigitalOcean Spaces" }
                    else if url.contains("linodeobjects.com") { "Linode Object Storage" }
                    else { "Unknown" };
                buckets.push(CloudBucket { url: url.clone(), provider: provider.into(), exists, accessible });
            }
        }
    }
}
