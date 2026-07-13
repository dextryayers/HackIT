use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

fn smtp_b64(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        out.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

pub async fn auth(target: &str, port: u16, user: &str, pass: &str, _to: u64) -> Result<bool, String> {
    let mut s = TcpStream::connect(format!("{}:{}", target, port))
        .await
        .map_err(|e| format!("conn:{}", e))?;
    let (r, mut w) = s.split();
    let mut br = BufReader::new(r);
    let mut buf = String::new();

    let _ = br.read_line(&mut buf).await;
    buf.clear();

    w.write_all(b"EHLO keystrike\r\n")
        .await
        .map_err(|e| e.to_string())?;
    let _ = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let mut line = String::new();
            if br.read_line(&mut line).await.unwrap_or(0) == 0 {
                break;
            }
            buf.push_str(&line);
            if !line.starts_with("250-") {
                break;
            }
        }
    })
    .await;

    if !buf.contains("AUTH") {
        return Err("no AUTH".into());
    }

    let auth_str = format!("{}\0{}\0{}", user, user, pass);
    let b64 = smtp_b64(auth_str.as_bytes());
    buf.clear();
    w.write_all(format!("AUTH PLAIN {}\r\n", b64).as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let _ = br.read_line(&mut buf).await;
    Ok(buf.starts_with("235"))
}
