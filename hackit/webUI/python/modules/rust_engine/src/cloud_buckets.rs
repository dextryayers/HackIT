use crate::common::*;
use crate::{progress, progress_done};

const BUCKET_PATTERNS: &[(&str, &[&str])] = &[
    ("AWS S3", &[
        "https://{target}-assets.s3.amazonaws.com",
        "https://{target}-backup.s3.amazonaws.com",
        "https://{target}-dev.s3.amazonaws.com",
        "https://{target}-prod.s3.amazonaws.com",
        "https://{target}-staging.s3.amazonaws.com",
        "https://{target}-cdn.s3.amazonaws.com",
        "https://{target}-media.s3.amazonaws.com",
        "https://{target}-static.s3.amazonaws.com",
        "https://{target}-uploads.s3.amazonaws.com",
        "https://{target}-files.s3.amazonaws.com",
        "https://{target}-data.s3.amazonaws.com",
        "https://{target}-public.s3.amazonaws.com",
        "https://{target}-private.s3.amazonaws.com",
        "https://{target}-logs.s3.amazonaws.com",
        "https://{target}-backup.s3.us-east-1.amazonaws.com",
        "https://{target}-backup.s3.us-west-2.amazonaws.com",
        "https://{target}-backup.s3.eu-west-1.amazonaws.com",
        "https://{target}.s3.amazonaws.com",
        "https://s3.amazonaws.com/{target}",
        "https://{target}-s3.amazonaws.com",
        "https://{target}-bucket.s3.amazonaws.com",
    ]),
    ("GCP Cloud Storage", &[
        "https://storage.googleapis.com/{target}",
        "https://storage.googleapis.com/{target}-data",
        "https://storage.googleapis.com/{target}-backup",
        "https://storage.googleapis.com/{target}-assets",
        "https://{target}.storage.googleapis.com",
        "https://{target}-storage.googleapis.com",
    ]),
    ("Azure Blob", &[
        "https://{target}.blob.core.windows.net",
        "https://{target}storage.blob.core.windows.net",
        "https://{target}data.blob.core.windows.net",
        "https://{target}backup.blob.core.windows.net",
        "https://{target}assets.blob.core.windows.net",
        "https://{target}-storage.blob.core.windows.net",
    ]),
    ("DigitalOcean Spaces", &[
        "https://{target}.digitaloceanspaces.com",
        "https://{target}-assets.digitaloceanspaces.com",
        "https://{target}-backup.digitaloceanspaces.com",
    ]),
    ("Linode Object Storage", &[
        "https://{target}.linodeobjects.com",
        "https://{target}-assets.linodeobjects.com",
    ]),
    ("Wasabi", &[
        "https://s3.wasabisys.com/{target}",
        "https://{target}.s3.wasabisys.com",
    ]),
    ("Backblaze B2", &[
        "https://f000.backblazeb2.com/file/{target}",
        "https://{target}.backblazeb2.com",
    ]),
];

pub async fn enumerate(target: &str) -> CloudBucketsResult {
    progress!("cloud_buckets", "running");
    let mut result = CloudBucketsResult { target: target.to_string(), buckets: vec![] };
    let base = target.split('.').next().unwrap_or(target).to_string();

    if let Some(client) = build_client(10) {
        for (provider, patterns) in BUCKET_PATTERNS {
            for pattern in *patterns {
                let bucket_url = pattern.replace("{target}", &base);
                match client.get(&bucket_url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let exists = status != 404 && status != 0;
                        let accessible = status < 400;
                        if exists {
                            result.buckets.push(BucketInfo {
                                url: bucket_url.clone(),
                                provider: provider.to_string(),
                                exists,
                                accessible,
                            });
                        }
                    }
                    Err(_) => {}
                }
                match client.head(&bucket_url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        if status != 404 && status != 0 && !result.buckets.iter().any(|b| b.url == bucket_url) {
                            result.buckets.push(BucketInfo {
                                url: bucket_url,
                                provider: provider.to_string(),
                                exists: true,
                                accessible: status < 400,
                            });
                        }
                    }
                    Err(_) => {}
                }
            }
        }
    }

    progress_done!("cloud_buckets");
    result
}
