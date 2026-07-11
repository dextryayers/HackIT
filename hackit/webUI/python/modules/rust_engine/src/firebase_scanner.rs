use crate::common::*;
use crate::{progress, progress_done};
use std::time::Duration;

const FIREBASE_PROJECT_PATTERNS: &[&str] = &[
    "{target}",
    "{target}-app",
    "{target}-dev",
    "{target}-prod",
    "{target}-staging",
    "{target}-test",
    "{target}-backup",
    "{target}-data",
    "{target}-db",
    "{target}-config",
    "{target}-firebase",
    "{target}-database",
    "{target}-default",
    "{target}-production",
    "{target}-development",
    "{target}-demo",
    "{target}-stage",
    "{target}-live",
    "{target}-api",
    "{target}-admin",
];

const CHECK_TIMEOUT_SECS: u64 = 10;

fn build_projects(target: &str) -> Vec<String> {
    let base = target.split('.').next().unwrap_or(target);
    let mut projects = Vec::new();
    for pat in FIREBASE_PROJECT_PATTERNS {
        projects.push(pat.replace("{target}", base));
    }
    projects
}

fn make_data_preview(body: &str) -> Option<String> {
    if body.len() > 200 {
        Some(format!("{}...", &body[..200]))
    } else {
        Some(body.to_string())
    }
}

async fn check_firebase_realtime(client: &reqwest::Client, project: &str) -> Option<FirebaseDatabase> {
    let url = format!("https://{}.firebaseio.com/.json", project);
    let resp = client.get(&url)
        .timeout(Duration::from_secs(CHECK_TIMEOUT_SECS))
        .send()
        .await
        .ok()?;
    let status = resp.status().as_u16();
    if status == 404 || status >= 500 {
        return None;
    }
    let accessible = status < 400;
    let body_text = resp.text().await.ok()?;
    let has_data = body_text.len() > 4 && !body_text.contains("\"error\"") && !body_text.contains("null");
    let data_preview = if has_data { make_data_preview(&body_text) } else { None };
    let security = if accessible { "open".to_string() } else { "restricted".to_string() };
    Some(FirebaseDatabase { url, accessible, has_data, data_preview, security })
}

async fn check_firestore(client: &reqwest::Client, project: &str) -> Option<FirebaseDatabase> {
    let url = format!(
        "https://firestore.googleapis.com/v1/projects/{}/databases/(default)/documents",
        project
    );
    let resp = client.get(&url)
        .timeout(Duration::from_secs(CHECK_TIMEOUT_SECS))
        .send()
        .await
        .ok()?;
    let status = resp.status().as_u16();
    if status == 404 || status >= 500 {
        return None;
    }
    let accessible = status < 400;
    let body_text = resp.text().await.ok()?;
    let has_data = body_text.len() > 10 && body_text.contains("\"documents\"");
    let data_preview = if has_data { make_data_preview(&body_text) } else { None };
    let security = if accessible { "open".to_string() } else { "restricted".to_string() };
    Some(FirebaseDatabase { url, accessible, has_data, data_preview, security })
}

async fn check_storage(client: &reqwest::Client, project: &str) -> Option<FirebaseDatabase> {
    let url = format!("https://storage.googleapis.com/{}.appspot.com", project);
    let resp = client.get(&url)
        .timeout(Duration::from_secs(CHECK_TIMEOUT_SECS))
        .send()
        .await
        .ok()?;
    let status = resp.status().as_u16();
    if status == 404 || status >= 500 {
        return None;
    }
    let accessible = status < 400;
    let body_text = resp.text().await.ok()?;
    let has_data = body_text.contains("Contents") || body_text.contains("Key") || body_text.len() > 50;
    let data_preview = if has_data { make_data_preview(&body_text) } else { None };
    let security = if accessible { "open".to_string() } else { "restricted".to_string() };
    Some(FirebaseDatabase { url, accessible, has_data, data_preview, security })
}

async fn check_auth(client: &reqwest::Client, project: &str) -> Option<FirebaseDatabase> {
    let url = "https://identitytoolkit.googleapis.com/v1/accounts:signUp".to_string();
    let params = [("key", format!("AIza{}", project))];
    let resp = client.post(&url)
        .form(&params)
        .timeout(Duration::from_secs(CHECK_TIMEOUT_SECS))
        .send()
        .await
        .ok()?;
    let status = resp.status().as_u16();
    if status == 404 || status >= 500 {
        return None;
    }
    let accessible = status < 400;
    let body_text = resp.text().await.ok()?;
    let has_data = body_text.len() > 10 && !body_text.contains("INVALID");
    let data_preview = if has_data { make_data_preview(&body_text) } else { None };
    let security = if accessible { "open".to_string() } else { "restricted".to_string() };
    Some(FirebaseDatabase { url, accessible, has_data, data_preview, security })
}

pub async fn scan(target: &str) -> FirebaseScanResult {
    progress!("firebase_scanner", "running");
    let mut result = FirebaseScanResult {
        project_id: target.to_string(),
        databases: Vec::new(),
        vulnerable: false,
        issues: Vec::new(),
        error: None,
    };

    let projects = build_projects(target);

    let client = match build_client(CHECK_TIMEOUT_SECS) {
        Some(c) => c,
        None => {
            result.error = Some("Failed to create HTTP client".to_string());
            progress_done!("firebase_scanner");
            return result;
        }
    };

    for project in &projects {
        if let Some(db) = check_firebase_realtime(&client, project).await {
            if db.accessible {
                result.vulnerable = true;
                result.issues.push(format!(
                    "Firebase Realtime Database open: {}.firebaseio.com/.json",
                    project
                ));
            }
            result.databases.push(db);
        }
        if let Some(db) = check_firestore(&client, project).await {
            if db.accessible {
                result.vulnerable = true;
                result.issues.push(format!(
                    "Firestore open: projects/{}/databases/(default)/documents",
                    project
                ));
            }
            result.databases.push(db);
        }
        if let Some(db) = check_storage(&client, project).await {
            if db.accessible {
                result.vulnerable = true;
                result.issues.push(format!(
                    "Firebase Storage open: {}.appspot.com",
                    project
                ));
            }
            result.databases.push(db);
        }
        if let Some(db) = check_auth(&client, project).await {
            if db.accessible {
                result.vulnerable = true;
                result.issues.push(format!(
                    "Firebase Auth API key exposed: AIza{}",
                    project
                ));
            }
            result.databases.push(db);
        }
    }

    progress_done!("firebase_scanner");
    result
}
