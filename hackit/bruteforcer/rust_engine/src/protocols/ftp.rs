//! FTP authentication over a raw control connection.
//!
//! `suppaftp` gives a typed client with PASV helpers we never use and a blocking
//! socket per call. The control channel is four lines of dialogue, so this speaks
//! it directly and keeps the per-attempt cost to one connect, two writes, and
//! two reads.
//!
//! `230` after PASS is a valid login. `530` is a refusal. Anything else is the
//! server telling us something unexpected, which is reported rather than guessed.

use crate::core::tls;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

async fn read_reply(
    reader: &mut BufReader<tokio::io::ReadHalf<tls::BoxStream>>,
    to: u64,
) -> Result<String, String> {
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(to), reader.read_line(&mut line))
        .await
        .map_err(|_| "read timeout".to_string())?
        .map_err(|e| format!("read: {}", e))?;
    if line.is_empty() {
        return Err("connection closed".into());
    }
    Ok(line)
}

fn code(line: &str) -> u16 {
    line.get(..3).and_then(|c| c.parse().ok()).unwrap_or(0)
}

pub async fn auth(
    target: &str,
    port: u16,
    user: &str,
    pass: &str,
    to: u64,
) -> Result<bool, String> {
    // Implicit FTPS (990) exists but is rare; explicit AUTH TLS is negotiated
    // in-band and not attempted here.
    let tls_on = port == 990;
    let stream = tls::connect(target, port, tls_on, to).await?;
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    let banner = read_reply(&mut reader, to).await?;
    if code(&banner) != 220 {
        return Err(format!("unexpected FTP banner: {}", banner.trim()));
    }

    write_half
        .write_all(format!("USER {}\r\n", user).as_bytes())
        .await
        .map_err(|e| format!("write: {}", e))?;
    let user_reply = read_reply(&mut reader, to).await?;
    match code(&user_reply) {
        230 => return Ok(true), // no password required
        331 => {}
        530 => return Ok(false),
        other => return Err(format!("USER rejected with {}", other)),
    }

    write_half
        .write_all(format!("PASS {}\r\n", pass).as_bytes())
        .await
        .map_err(|e| format!("write: {}", e))?;
    let pass_reply = read_reply(&mut reader, to).await?;

    // Best-effort QUIT; the verdict is already known.
    let _ = write_half.write_all(b"QUIT\r\n").await;

    match code(&pass_reply) {
        230 | 202 => Ok(true),
        530 | 421 | 500 | 501 | 503 => Ok(false),
        other => Err(format!("PASS rejected with {}", other)),
    }
}
