use std::time::Duration;
use tiberius::{AuthMethod, Client, Config};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

pub async fn auth(target: &str, port: u16, user: &str, pass: &str, to: u64) -> Result<bool, String> {
    let mut config = Config::new();
    config.host(target);
    config.port(port);
    config.authentication(AuthMethod::sql_server(&user, &pass));
    config.trust_cert();

    let tcp = tokio::time::timeout(
        Duration::from_secs(to),
        TcpStream::connect(format!("{}:{}", target, port)),
    )
    .await
    .map_err(|_| "timeout".to_string())?
    .map_err(|e| format!("conn: {}", e))?;

    let client = tokio::time::timeout(
        Duration::from_secs(to),
        Client::connect(config, tcp.compat_write()),
    )
    .await
    .map_err(|_| "timeout".to_string())?
    .map_err(|e| format!("mssql: {}", e))?;

    let _ = client.close().await;
    Ok(true)
}
