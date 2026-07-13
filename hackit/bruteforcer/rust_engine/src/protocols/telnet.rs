use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

pub async fn auth(target: &str, port: u16, user: &str, pass: &str, to: u64) -> Result<bool, String> {
    let mut s = tokio::time::timeout(
        Duration::from_secs(to),
        TcpStream::connect(format!("{}:{}", target, port)),
    )
    .await
    .map_err(|_| "timeout".to_string())?
    .map_err(|e| format!("conn:{}", e))?;

    let (r, mut w) = s.split();
    let mut br = BufReader::new(r);
    let mut buf = String::new();

    let _ = tokio::time::timeout(Duration::from_secs(2), br.read_line(&mut buf)).await;
    buf.clear();

    w.write_all(format!("{}\r\n", user).as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), br.read_line(&mut buf)).await;
    buf.clear();

    w.write_all(format!("{}\r\n", pass).as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), br.read_line(&mut buf)).await;

    let l = buf.to_lowercase();
    Ok(l.contains('$')
        || l.contains('#')
        || l.contains('>')
        || l.contains("welcome")
        || (!l.contains("login") && !l.contains("password") && !buf.is_empty()))
}
