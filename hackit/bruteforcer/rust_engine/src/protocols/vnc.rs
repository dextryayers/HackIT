//! VNC authentication (RFB 3.3 / 3.7 / 3.8).
//!
//! VNC's challenge-response is DES-ECB over a 16-byte server nonce, keyed by
//! the password padded to 8 bytes with NULs and **bit-reversed byte by byte**.
//! The previous implementation's `des_feistel` was a multiply-rotate toy — it
//! produced plausible-looking bytes and never authenticated once. This uses a
//! real DES implementation, so the response is the response a VNC server expects.
//!
//! Password length is capped at 8 bytes by the protocol itself; longer input is
//! truncated exactly as the server does.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SECURITY_NONE: u8 = 1;
const SECURITY_VNC: u8 = 2;

fn reverse_bits(byte: u8) -> u8 {
    byte.reverse_bits()
}

fn vnc_key(pass: &str) -> [u8; 8] {
    let mut key = [0u8; 8];
    for (i, b) in pass.bytes().take(8).enumerate() {
        key[i] = reverse_bits(b);
    }
    key
}

fn encrypt_challenge(key: &[u8; 8], challenge: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for block in 0..2 {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&challenge[block * 8..block * 8 + 8]);
        out[block * 8..block * 8 + 8].copy_from_slice(&crate::core::des::encrypt_block(*key, chunk));
    }
    out
}

async fn read_exact_to(
    stream: &mut TcpStream,
    buf: &mut [u8],
    to: u64,
) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(to), stream.read_exact(buf))
        .await
        .map_err(|_| "read timeout".to_string())?
        .map(|_| ())
        .map_err(|e| format!("read: {}", e))
}

pub async fn auth(
    target: &str,
    port: u16,
    _user: &str,
    pass: &str,
    to: u64,
) -> Result<bool, String> {
    let mut stream = tokio::time::timeout(
        Duration::from_secs(to),
        TcpStream::connect(format!("{}:{}", target, port)),
    )
    .await
    .map_err(|_| "connect timeout".to_string())?
    .map_err(|e| format!("connect: {}", e))?;
    let _ = stream.set_nodelay(true);

    let mut banner = [0u8; 12];
    read_exact_to(&mut stream, &mut banner, to).await?;
    let version = String::from_utf8_lossy(&banner);
    if !version.starts_with("RFB ") {
        return Err(format!("not a VNC server (banner {:?})", version.trim()));
    }

    let major = version
        .get(4..7)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let minor = version
        .get(8..11)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    // Negotiate 3.8 when offered; 3.3 has no security-type list.
    let chosen = match (major, minor) {
        (3, m) if m >= 8 => "RFB 003.008\n",
        (3, 7) => "RFB 003.007\n",
        _ => "RFB 003.003\n",
    };
    stream
        .write_all(chosen.as_bytes())
        .await
        .map_err(|e| format!("version: {}", e))?;

    let security_type: u8 = if chosen == "RFB 003.003\n" {
        let mut raw = [0u8; 4];
        read_exact_to(&mut stream, &mut raw, to).await?;
        let t = u32::from_be_bytes(raw);
        match t {
            0 => return Err("VNC server refused the connection".into()),
            1 => SECURITY_NONE,
            2 => SECURITY_VNC,
            other => return Err(format!("VNC unsupported security type {}", other)),
        }
    } else {
        let mut count = [0u8; 1];
        read_exact_to(&mut stream, &mut count, to).await?;
        if count[0] == 0 {
            // 3.8 sends a reason string after a zero count.
            let mut len = [0u8; 4];
            let _ = read_exact_to(&mut stream, &mut len, to).await;
            return Err("VNC server offered no security types".into());
        }
        let mut types = vec![0u8; count[0] as usize];
        read_exact_to(&mut stream, &mut types, to).await?;
        if types.contains(&SECURITY_VNC) {
            stream
                .write_all(&[SECURITY_VNC])
                .await
                .map_err(|e| format!("security: {}", e))?;
            SECURITY_VNC
        } else if types.contains(&SECURITY_NONE) {
            stream
                .write_all(&[SECURITY_NONE])
                .await
                .map_err(|e| format!("security: {}", e))?;
            SECURITY_NONE
        } else {
            return Err(format!("VNC offered no supported auth (types {:?})", types));
        }
    };

    match security_type {
        SECURITY_NONE => Err("VNC requires no password".into()),
        SECURITY_VNC => {
            let mut challenge = [0u8; 16];
            read_exact_to(&mut stream, &mut challenge, to).await?;
            let key = vnc_key(pass);
            let response = encrypt_challenge(&key, &challenge);
            stream
                .write_all(&response)
                .await
                .map_err(|e| format!("response: {}", e))?;

            let mut verdict = [0u8; 4];
            read_exact_to(&mut stream, &mut verdict, to).await?;
            // 0 = OK, 1 = failed, 2 = too many attempts.
            Ok(u32::from_be_bytes(verdict) == 0)
        }
        _ => Err("VNC: unknown auth scheme".into()),
    }
}
