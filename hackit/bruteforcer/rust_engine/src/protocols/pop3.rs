//! POP3 authentication — USER/PASS, implicit TLS on 995.

use crate::core::tls;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

async fn read_line(
    reader: &mut BufReader<tokio::io::ReadHalf<tls::BoxStream>>,
    to: u64,
) -> Result<String, String> {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(to), reader.read_line(&mut line))
        .await
        .map_err(|_| "read timeout".to_string())?
        .map_err(|e| format!("read: {}", e))?;
    if n == 0 {
        return Err("connection closed".into());
    }
    Ok(line)
}

pub async fn auth(
    target: &str,
    port: u16,
    user: &str,
    pass: &str,
    to: u64,
) -> Result<bool, String> {
    let tls_on = port == 995 || port == 8995;
    let stream = tls::connect(target, port, tls_on, to).await?;
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    let banner = read_line(&mut reader, to).await?;
    if !banner.starts_with("+OK") {
        return Err(format!("unexpected POP3 banner: {}", banner.trim()));
    }

    write_half
        .write_all(format!("USER {}\r\n", user).as_bytes())
        .await
        .map_err(|e| format!("write: {}", e))?;
    let user_reply = read_line(&mut reader, to).await?;
    if !user_reply.starts_with("+OK") {
        // Some servers do not reveal whether the mailbox exists.
        return Ok(false);
    }

    write_half
        .write_all(format!("PASS {}\r\n", pass).as_bytes())
        .await
        .map_err(|e| format!("write: {}", e))?;
    let pass_reply = read_line(&mut reader, to).await?;

    let _ = write_half.write_all(b"QUIT\r\n").await;
    Ok(pass_reply.starts_with("+OK"))
}
