//! IMAP authentication — LOGIN, implicit TLS on 993.

use crate::core::tls;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// IMAP quoted string: backslash and double quote are the only escapes.
fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        if ch == '"' || ch == '\\' {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
    out
}

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
    let tls_on = port == 993 || port == 8993;
    let stream = tls::connect(target, port, tls_on, to).await?;
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    // Greeting: `* OK ...` (some servers send `* PREAUTH` when already logged in).
    let greeting = read_line(&mut reader, to).await?;
    if greeting.starts_with("* PREAUTH") {
        return Err("IMAP server pre-authenticated the session".into());
    }
    if !greeting.starts_with("* OK") {
        return Err(format!("unexpected IMAP greeting: {}", greeting.trim()));
    }

    let tag = "a001";
    let tag_upper = tag.to_ascii_uppercase();
    write_half
        .write_all(
            format!("{} LOGIN {} {}\r\n", tag, quote(user), quote(pass)).as_bytes(),
        )
        .await
        .map_err(|e| format!("write: {}", e))?;

    // The tagged reply terminates the exchange; untagged lines are skipped.
    loop {
        let line = read_line(&mut reader, to).await?;
        let upper = line.to_ascii_uppercase();
        if !upper.starts_with(&tag_upper) {
            continue;
        }
        let _ = write_half.write_all(b"a002 LOGOUT\r\n").await;
        return Ok(upper.starts_with(&format!("{} OK", tag_upper)));
    }
}
