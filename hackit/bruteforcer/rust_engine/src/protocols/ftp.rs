use std::time::Duration;

pub async fn auth(target: &str, port: u16, user: &str, pass: &str, to: u64) -> Result<bool, String> {
    use suppaftp::FtpStream;
    let addr = format!("{}:{}", target, port);
    let u = user.to_string();
    let p = pass.to_string();
    tokio::time::timeout(Duration::from_secs(to), async {
        tokio::task::spawn_blocking(move || {
            let mut c = FtpStream::connect(&addr).map_err(|e| e.to_string())?;
            c.login(&u, &p).map_err(|e| e.to_string())?;
            let _ = c.quit();
            Ok(true)
        })
        .await
        .map_err(|e| e.to_string())?
    })
    .await
    .map_err(|_| "timeout".to_string())?
    .map_err(|e| e)
}
