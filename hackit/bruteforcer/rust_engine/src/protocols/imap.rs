use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

pub async fn auth(target: &str, port: u16, user: &str, pass: &str, _to: u64) -> Result<bool, String> {
    let mut s = TcpStream::connect(format!("{}:{}", target, port))
        .await
        .map_err(|e| e.to_string())?;
    let (r, mut w) = s.split();
    let mut br = BufReader::new(r);
    let mut buf = String::new();

    let _ = br.read_line(&mut buf).await;
    buf.clear();

    w.write_all(format!("a001 LOGIN {} {}\r\n", user, pass).as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let _ = br.read_line(&mut buf).await;

    Ok(buf.to_lowercase().contains("a001 ok") || buf.contains("LOGGEDIN"))
}
