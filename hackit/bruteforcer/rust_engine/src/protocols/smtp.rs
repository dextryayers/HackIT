//! SMTP authentication — PLAIN with a LOGIN fallback, implicit TLS on 465.

use crate::core::tls;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

fn b64(input: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(input)
}

/// Read a (possibly multiline) SMTP reply and return the numeric code of the
/// final line.
async fn read_reply(
    reader: &mut BufReader<tokio::io::ReadHalf<tls::BoxStream>>,
    to: u64,
) -> Result<(u16, String), String> {
    let mut collected = String::new();
    loop {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(to), reader.read_line(&mut line))
            .await
            .map_err(|_| "read timeout".to_string())?
            .map_err(|e| format!("read: {}", e))?;
        if n == 0 {
            return Err("connection closed".into());
        }
        collected.push_str(&line);
        // Continuation lines have '-' as the fourth character.
        if line.len() < 4 || line.as_bytes()[3] != b'-' {
            let code = line
                .get(..3)
                .and_then(|c| c.parse::<u16>().ok())
                .unwrap_or(0);
            return Ok((code, collected));
        }
        if collected.len() > 16_384 {
            return Err("SMTP reply too long".into());
        }
    }
}

pub async fn auth(
    target: &str,
    port: u16,
    user: &str,
    pass: &str,
    to: u64,
) -> Result<bool, String> {
    let tls_on = matches!(port, 465 | 587) || port == 8465;
    let stream = tls::connect(target, port, tls_on, to).await?;
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    let (greeting, _) = read_reply(&mut reader, to).await?;
    if greeting != 220 {
        return Err(format!("unexpected SMTP greeting {}", greeting));
    }

    write_half
        .write_all(b"EHLO keystrike\r\n")
        .await
        .map_err(|e| format!("write: {}", e))?;
    let (code, capabilities) = read_reply(&mut reader, to).await?;
    if code != 250 {
        return Err(format!("EHLO rejected with {}", code));
    }
    if !capabilities.to_ascii_uppercase().contains("AUTH") {
        return Err("server does not advertise AUTH".into());
    }

    // PLAIN first: one round trip, accepted by every modern server.
    let plain = b64(format!("\0{}\0{}", user, pass).as_bytes());
    write_half
        .write_all(format!("AUTH PLAIN {}\r\n", plain).as_bytes())
        .await
        .map_err(|e| format!("write: {}", e))?;
    let (code, reply) = read_reply(&mut reader, to).await?;

    match code {
        235 => return Ok(true),
        535 | 534 | 530 => return Ok(false),
        504 => {
            // PLAIN not implemented — fall back to LOGIN.
        }
        501 | 500 => {
            // Malformed or unknown — fall back too.
        }
        other => {
            if reply.to_ascii_uppercase().contains("ALREADY AUTHENTICATED") {
                return Ok(true);
            }
            return Err(format!("AUTH PLAIN rejected with {}", other));
        }
    }

    write_half
        .write_all(b"AUTH LOGIN\r\n")
        .await
        .map_err(|e| format!("write: {}", e))?;
    let (code, _) = read_reply(&mut reader, to).await?;
    if code != 334 {
        return Err(format!("AUTH LOGIN rejected with {}", code));
    }

    write_half
        .write_all(format!("{}\r\n", b64(user.as_bytes())).as_bytes())
        .await
        .map_err(|e| format!("write: {}", e))?;
    let (code, _) = read_reply(&mut reader, to).await?;
    if code != 334 {
        return Ok(false);
    }

    write_half
        .write_all(format!("{}\r\n", b64(pass.as_bytes())).as_bytes())
        .await
        .map_err(|e| format!("write: {}", e))?;
    let (code, _) = read_reply(&mut reader, to).await?;

    let _ = write_half.write_all(b"QUIT\r\n").await;
    Ok(code == 235)
}
