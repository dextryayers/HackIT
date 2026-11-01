//! Redis authentication over a raw RESP connection.
//!
//! The `redis` crate builds a multiplexed connection with background tasks and
//! reconnect logic — correct for an application, ruinous for a brute forcer
//! that opens one socket per candidate. RESP is four lines of framing; we speak
//! it directly and drop the socket the moment the verdict is in.
//!
//! Two dialects exist in the wild:
//!   * Redis < 6.0 — `AUTH <password>`
//!   * Redis >= 6.0 ACL — `AUTH <username> <password>`
//! We try the ACL form first and fall back when the server says the arity is
//! wrong, so both answer correctly.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn resp_command(parts: &[&str]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", parts.len()).into_bytes();
    for part in parts {
        out.extend_from_slice(format!("${}\r\n", part.len()).as_bytes());
        out.extend_from_slice(part.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Read one RESP reply. Returns (prefix, payload) where prefix is `+`, `-`, `:`,
/// `$`, or `*`. Enough to tell `+OK` from `-ERR`.
async fn read_reply(stream: &mut TcpStream, to: u64) -> Result<(u8, String), String> {
    let mut first = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(to), stream.read_exact(&mut first))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| format!("read: {}", e))?;

    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        tokio::time::timeout(Duration::from_secs(to), stream.read_exact(&mut byte))
            .await
            .map_err(|_| "timeout".to_string())?
            .map_err(|e| format!("read: {}", e))?;
        if byte[0] == b'\r' {
            let mut lf = [0u8; 1];
            let _ = stream.read_exact(&mut lf).await;
            break;
        }
        line.push(byte[0]);
        if line.len() > 4096 {
            return Err("reply too long".into());
        }
    }
    Ok((first[0], String::from_utf8_lossy(&line).to_string()))
}

async fn attempt(
    target: &str,
    port: u16,
    parts: &[&str],
    to: u64,
) -> Result<(u8, String), String> {
    let mut stream = tokio::time::timeout(
        Duration::from_secs(to),
        TcpStream::connect(format!("{}:{}", target, port)),
    )
    .await
    .map_err(|_| "connect timeout".to_string())?
    .map_err(|e| format!("connect: {}", e))?;
    let _ = stream.set_nodelay(true);

    let cmd = resp_command(parts);
    tokio::time::timeout(Duration::from_secs(to), stream.write_all(&cmd))
        .await
        .map_err(|_| "write timeout".to_string())?
        .map_err(|e| format!("write: {}", e))?;

    read_reply(&mut stream, to).await
}

pub async fn auth(
    target: &str,
    port: u16,
    user: &str,
    pass: &str,
    to: u64,
) -> Result<bool, String> {
    // ACL form first.
    let (prefix, payload) = attempt(target, port, &["AUTH", user, pass], to).await?;
    if prefix == b'+' {
        return Ok(true);
    }
    let low = payload.to_ascii_lowercase();

    // Wrong arity means this is a pre-ACL server: retry as a bare password.
    if low.contains("wrong number of arguments") {
        let (p2, body2) = attempt(target, port, &["AUTH", pass], to).await?;
        if p2 == b'+' {
            return Ok(true);
        }
        let low2 = body2.to_ascii_lowercase();
        if low2.contains("without any password configured")
            || low2.contains("no password is set")
            || low2.contains("client sent auth, but no password is set")
        {
            return Err("redis has no password configured".into());
        }
        return Ok(false);
    }

    if low.contains("without any password configured") || low.contains("no password is set") {
        return Err("redis has no password configured".into());
    }

    // `-WRONGPASS` and `-ERR invalid password` both mean "denied".
    Ok(false)
}
