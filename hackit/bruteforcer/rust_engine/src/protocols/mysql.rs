//! MySQL / MariaDB authentication over the wire protocol.
//!
//! `sqlx` opens a pool per candidate: TLS negotiation, background ping task,
//! statement cache, graceful close. At brute-force concurrency that overhead
//! dominates. This speaks the handshake directly and supports the three auth
//! plugins that actually appear in the wild:
//!
//!   * `mysql_native_password` — SHA1(password) XOR SHA1(scramble || SHA1(SHA1(password)))
//!   * `caching_sha2_password` — SHA256 fast path, RSA full path
//!   * `mysql_clear_password` — only accepted over TLS by default, but some
//!     servers enable it on loopback
//!
//! A `0x00` packet is OK, `0xFF` is an error packet, `0xFE` is an auth switch.

use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
const CLIENT_FOUND_ROWS: u32 = 0x0000_0002;
const CLIENT_LONG_FLAG: u32 = 0x0000_0004;
const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_TRANSACTIONS: u32 = 0x0000_2000;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_MULTI_RESULTS: u32 = 0x0002_0000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;

const MAX_PACKET: u32 = 16 * 1024 * 1024;

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

fn native_password(password: &str, scramble: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let stage1 = sha1(password.as_bytes());
    let stage2 = sha1(&stage1);
    let mut seeded = Vec::with_capacity(scramble.len() + stage2.len());
    seeded.extend_from_slice(scramble);
    seeded.extend_from_slice(&stage2);
    let stage3 = sha1(&seeded);
    xor(&stage1, &stage3)
}

fn caching_sha2_password(password: &str, scramble: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let stage1 = sha256(password.as_bytes());
    let stage2 = sha256(&stage1);
    let mut seeded = Vec::with_capacity(stage2.len() + scramble.len());
    seeded.extend_from_slice(&stage2);
    seeded.extend_from_slice(scramble);
    let stage3 = sha256(&seeded);
    xor(&stage1, &stage3)
}

fn scramble_password(plugin: &str, password: &str, scramble: &[u8]) -> Result<Vec<u8>, String> {
    match plugin {
        "mysql_native_password" => Ok(native_password(password, scramble)),
        "caching_sha2_password" => Ok(caching_sha2_password(password, scramble)),
        "mysql_clear_password" => {
            let mut out = password.as_bytes().to_vec();
            out.push(0);
            Ok(out)
        }
        "sha256_password" => {
            // Requires the server's RSA key; handled by the caller after a
            // public-key request, not here.
            Ok(Vec::new())
        }
        other => Err(format!("unsupported auth plugin: {}", other)),
    }
}

async fn read_packet(stream: &mut TcpStream, to: u64) -> Result<Vec<u8>, String> {
    let mut header = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(to), stream.read_exact(&mut header))
        .await
        .map_err(|_| "read timeout".to_string())?
        .map_err(|e| format!("read: {}", e))?;
    let len = (header[0] as usize) | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
    if len == 0 || len > MAX_PACKET as usize {
        return Err(format!("bad packet length {}", len));
    }
    let mut body = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(to), stream.read_exact(&mut body))
        .await
        .map_err(|_| "read timeout".to_string())?
        .map_err(|e| format!("read: {}", e))?;
    Ok(body)
}

async fn write_packet(stream: &mut TcpStream, payload: &[u8], to: u64) -> Result<(), String> {
    let mut packet = Vec::with_capacity(payload.len() + 4);
    packet.push((payload.len() & 0xFF) as u8);
    packet.push(((payload.len() >> 8) & 0xFF) as u8);
    packet.push(((payload.len() >> 16) & 0xFF) as u8);
    packet.push(0); // sequence id is overwritten per exchange by the caller
    packet.extend_from_slice(payload);
    tokio::time::timeout(Duration::from_secs(to), stream.write_all(&packet))
        .await
        .map_err(|_| "write timeout".to_string())?
        .map_err(|e| format!("write: {}", e))
}

/// Sequence id matters: the handshake response must carry seq 1, every
/// subsequent client packet increments.
async fn write_packet_seq(
    stream: &mut TcpStream,
    payload: &[u8],
    seq: u8,
    to: u64,
) -> Result<(), String> {
    let mut packet = Vec::with_capacity(payload.len() + 4);
    packet.push((payload.len() & 0xFF) as u8);
    packet.push(((payload.len() >> 8) & 0xFF) as u8);
    packet.push(((payload.len() >> 16) & 0xFF) as u8);
    packet.push(seq);
    packet.extend_from_slice(payload);
    tokio::time::timeout(Duration::from_secs(to), stream.write_all(&packet))
        .await
        .map_err(|_| "write timeout".to_string())?
        .map_err(|e| format!("write: {}", e))
}

struct Handshake {
    capabilities: u32,
    plugin: String,
    scramble: Vec<u8>,
}

fn parse_handshake(body: &[u8]) -> Result<Handshake, String> {
    if body.is_empty() || body[0] != 10 {
        return Err(format!(
            "not a MySQL handshake (protocol {:?})",
            body.first()
        ));
    }
    let mut i = 1;
    while i < body.len() && body[i] != 0 {
        i += 1;
    }
    if i >= body.len() {
        return Err("truncated handshake".into());
    }
    i += 1; // NUL after server version
    i += 4; // connection id

    if i + 8 > body.len() {
        return Err("truncated scramble part 1".into());
    }
    let mut scramble = body[i..i + 8].to_vec();
    i += 8;
    i += 1; // filler

    if i + 2 > body.len() {
        return Err("truncated capability flags".into());
    }
    let caps_lower = u16::from_le_bytes([body[i], body[i + 1]]) as u32;
    i += 2;

    if i + 1 + 2 + 2 + 1 + 10 > body.len() {
        // Pre-4.1 server: capabilities end here.
        return Ok(Handshake {
            capabilities: caps_lower,
            plugin: "mysql_native_password".into(),
            scramble,
        });
    }
    i += 1; // charset
    i += 2; // status flags
    let caps_upper = u16::from_le_bytes([body[i], body[i + 1]]) as u32;
    i += 2;
    let capabilities = caps_lower | (caps_upper << 16);

    let auth_len = body[i] as usize;
    i += 1;
    i += 10; // reserved

    if capabilities & CLIENT_SECURE_CONNECTION != 0 {
        let part2_len = auth_len.saturating_sub(8).max(13).min(body.len().saturating_sub(i));
        if part2_len > 0 && i + part2_len <= body.len() {
            // The final byte is a NUL terminator, not scramble material.
            let take = part2_len.saturating_sub(1);
            scramble.extend_from_slice(&body[i..i + take]);
            i += part2_len;
        }
    }

    let plugin = if capabilities & CLIENT_PLUGIN_AUTH != 0 && i < body.len() {
        let start = i;
        while i < body.len() && body[i] != 0 {
            i += 1;
        }
        String::from_utf8_lossy(&body[start..i]).to_string()
    } else {
        "mysql_native_password".to_string()
    };

    Ok(Handshake {
        capabilities,
        plugin: if plugin.is_empty() {
            "mysql_native_password".to_string()
        } else {
            plugin
        },
        scramble,
    })
}

fn handshake_response(
    user: &str,
    auth: &[u8],
    database: &str,
    plugin: &str,
    capabilities: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(128 + auth.len());
    out.extend_from_slice(&capabilities.to_le_bytes());
    out.extend_from_slice(&MAX_PACKET.to_le_bytes());
    out.push(33); // utf8_general_ci
    out.extend_from_slice(&[0u8; 23]);
    out.extend_from_slice(user.as_bytes());
    out.push(0);
    // CLIENT_SECURE_CONNECTION: one length byte, then the response.
    out.push(auth.len() as u8);
    out.extend_from_slice(auth);
    if capabilities & CLIENT_CONNECT_WITH_DB != 0 {
        out.extend_from_slice(database.as_bytes());
        out.push(0);
    }
    if capabilities & CLIENT_PLUGIN_AUTH != 0 {
        out.extend_from_slice(plugin.as_bytes());
        out.push(0);
    }
    out
}

fn error_text(body: &[u8]) -> String {
    // 0xFF, error code (2), '#', SQLSTATE (5), message.
    if body.len() > 9 && body[3] == b'#' {
        String::from_utf8_lossy(&body[9..]).to_string()
    } else if body.len() > 3 {
        String::from_utf8_lossy(&body[3..]).to_string()
    } else {
        "authentication failed".to_string()
    }
}

/// `caching_sha2_password` full auth: request the server's RSA key, XOR the
/// password with the scramble, and encrypt with PKCS#1 v1.5.
async fn caching_sha2_full_auth(
    stream: &mut TcpStream,
    password: &str,
    scramble: &[u8],
    to: u64,
) -> Result<bool, String> {
    // 0x02 = request public key.
    write_packet_seq(stream, &[0x02], 3, to).await?;
    let body = read_packet(stream, to).await?;
    if body.first() == Some(&0xFF) {
        return Err(format!("mysql: {}", error_text(&body)));
    }
    if body.first() != Some(&0x01) {
        return Err("expected RSA public key".into());
    }
    let pem = String::from_utf8_lossy(&body[1..]).to_string();
    let key = RsaPublicKey::from_public_key_pem(&pem)
        .map_err(|e| format!("bad RSA public key: {}", e))?;

    let mut plain = password.as_bytes().to_vec();
    plain.push(0);
    let masked = xor(&plain, &scramble.iter().copied().cycle().take(plain.len()).collect::<Vec<_>>());
    let encrypted = key
        .encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, &masked)
        .map_err(|e| format!("RSA encrypt: {}", e))?;

    write_packet_seq(stream, &encrypted, 5, to).await?;
    let body = read_packet(stream, to).await?;
    Ok(body.first() == Some(&0x00))
}

pub async fn auth(
    target: &str,
    port: u16,
    user: &str,
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

    let greeting = read_packet(&mut stream, to).await?;
    if greeting.first() == Some(&0xFF) {
        return Err(format!("mysql: {}", error_text(&greeting)));
    }
    let handshake = parse_handshake(&greeting)?;

    let mut capabilities = CLIENT_LONG_PASSWORD
        | CLIENT_FOUND_ROWS
        | CLIENT_LONG_FLAG
        | CLIENT_PROTOCOL_41
        | CLIENT_TRANSACTIONS
        | CLIENT_SECURE_CONNECTION
        | CLIENT_MULTI_RESULTS
        | CLIENT_PLUGIN_AUTH
        | CLIENT_CONNECT_WITH_DB;
    // Only advertise what the server offers.
    capabilities &= handshake.capabilities | CLIENT_PROTOCOL_41;

    let auth_response = scramble_password(&handshake.plugin, pass, &handshake.scramble)?;
    let response = handshake_response(user, &auth_response, "mysql", &handshake.plugin, capabilities);
    write_packet_seq(&mut stream, &response, 1, to).await?;

    let mut seq = 2u8;
    let mut plugin = handshake.plugin.clone();
    let mut scramble = handshake.scramble.clone();

    loop {
        let body = read_packet(&mut stream, to).await?;
        match body.first().copied() {
            Some(0x00) => return Ok(true),
            Some(0xFF) => {
                let text = error_text(&body);
                let low = text.to_ascii_lowercase();
                if low.contains("access denied")
                    || low.contains("password")
                    || low.contains("authentication")
                    || low.contains("user")
                {
                    return Ok(false);
                }
                return Err(format!("mysql: {}", text));
            }
            Some(0xFE) => {
                // Auth switch request: plugin name + new scramble.
                if body.len() < 2 {
                    return Ok(false);
                }
                let rest = &body[1..];
                let end = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
                plugin = String::from_utf8_lossy(&rest[..end]).to_string();
                scramble = if end + 1 < rest.len() {
                    let mut s = rest[end + 1..].to_vec();
                    while s.last() == Some(&0) {
                        s.pop();
                    }
                    s
                } else {
                    Vec::new()
                };
                seq = seq.wrapping_add(1);
                let response = scramble_password(&plugin, pass, &scramble)?;
                if response.is_empty() && plugin == "sha256_password" {
                    return caching_sha2_full_auth(&mut stream, pass, &scramble, to).await;
                }
                write_packet_seq(&mut stream, &response, seq, to).await?;
            }
            Some(0x01) => {
                // AuthMoreData.
                match body.get(1).copied() {
                    Some(0x03) => return Ok(true), // fast auth succeeded
                    Some(0x04) => {
                        return caching_sha2_full_auth(&mut stream, pass, &scramble, to).await;
                    }
                    _ => {
                        seq = seq.wrapping_add(1);
                        continue;
                    }
                }
            }
            _ => {
                // Unknown packet — treat as a failed login rather than a crash.
                return Ok(false);
            }
        }
    }
}
