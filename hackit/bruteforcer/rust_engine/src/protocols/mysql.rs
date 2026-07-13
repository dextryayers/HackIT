use std::time::Duration;

pub async fn auth(target: &str, port: u16, user: &str, pass: &str, to: u64) -> Result<bool, String> {
    let opts = sqlx::mysql::MySqlConnectOptions::new()
        .host(target)
        .port(port)
        .username(user)
        .password(pass)
        .database("mysql");
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(to))
        .connect_with(opts)
        .await;
    match pool {
        Ok(p) => {
            let _ = p.close().await;
            Ok(true)
        }
        Err(e) => Err(e.to_string()),
    }
}
