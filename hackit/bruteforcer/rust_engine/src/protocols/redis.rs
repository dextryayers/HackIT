pub async fn auth(target: &str, port: u16, user: &str, pass: &str, _to: u64) -> Result<bool, String> {
    let cs = format!("redis://{}:{}@{}:{}/", user, pass, target, port);
    redis::Client::open(cs.as_str())
        .map_err(|e| e.to_string())?
        .get_connection()
        .map(|_| true)
        .map_err(|e| e.to_string())
}
