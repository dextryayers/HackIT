use std::time::Duration;

pub async fn auth(target: &str, port: u16, user: &str, pass: &str, to: u64) -> Result<bool, String> {
    let proto = if port == 443 { "https" } else { "http" };
    let url = format!("{}://{}:{}", proto, target, port);
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(to))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .get(&url)
        .basic_auth(user, Some(pass))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    Ok(resp.status().as_u16() != 401 && resp.status().as_u16() != 403)
}
