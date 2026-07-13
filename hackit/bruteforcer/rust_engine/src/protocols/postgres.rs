use std::time::Duration;

pub async fn auth(target: &str, port: u16, user: &str, pass: &str, to: u64) -> Result<bool, String> {
    let cs = format!(
        "postgresql://{}:{}@{}:{}/postgres",
        user, pass, target, port
    );
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(to))
        .connect(&cs)
        .await;
    match pool {
        Ok(p) => {
            let _ = p.close().await;
            Ok(true)
        }
        Err(e) => Err(e.to_string()),
    }
}
