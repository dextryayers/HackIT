//! PostgreSQL authentication over the wire protocol.
//!
//! `sqlx` builds a pool per attempt: TLS context, background tasks, health
//! checks, teardown. For a brute forcer that is roughly two orders of magnitude
//! of wasted work per candidate. The startup packet and the three auth methods
//! that matter are small enough to speak directly:
//!
//!   * `AuthenticationCleartextPassword` (3)
//!   * `AuthenticationMD5Password` (5)
//!   * `AuthenticationSASL` → SCRAM-SHA-256 (10/11/12)
//!
//! A successful login ends with `AuthenticationOk` (subtype 0) or the SASL final
//! message carrying a matching server signature. An `ErrorResponse` anywhere in
//! the exchange is a denial.

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

type HmacSha256 = Hmac<Sha256>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn md5_hex(data: &[u8]) -> String {
    use md5::{Digest as _, Md5};
    let mut hasher = Md5::new();
    hasher.update(data);
    hex(&hasher.finalize())
}

/// `md5(md5(password + user) || salt)` with the `md5` prefix the server expects.
fn md5_password(user: &str, pass: &str, salt: &[u8]) -> String {
    let inner = md5_hex(format!("{}{}", pass, user).as_bytes());
    let mut outer = Vec::with_capacity(inner.len() + salt.len());
    outer.extend_from_slice(inner.as_bytes());
    outer.extend_from_slice(salt);
    format!("md5{}", md5_hex(&outer))
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(password).expect("HMAC accepts any key length");
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut block = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&block);

    for _ in 1..iterations {
        let mut mac = HmacSha256::new_from_slice(password).expect("HMAC accepts any key length");
        mac.update(&block);
        block = mac.finalize().into_bytes();
        for (o, b) in out.iter_mut().zip(block.iter()) {
            *o ^= b;
        }
    }
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

struct Reader {
    stream: TcpStream,
    to: u64,
}

impl Reader {
    /// Read one backend message: 1 type byte, 4 length bytes, payload.
    async fn message(&mut self) -> Result<(u8, Vec<u8>), String> {
        let mut header = [0u8; 5];
        tokio::time::timeout(Duration::from_secs(self.to), self.stream.read_exact(&mut header))
            .await
            .map_err(|_| "read timeout".to_string())?
            .map_err(|e| format!("read: {}", e))?;
        let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        if !(4..=1_048_576).contains(&len) {
            return Err(format!("bad message length {}", len));
        }
        let mut body = vec![0u8; len - 4];
        if !body.is_empty() {
            tokio::time::timeout(
                Duration::from_secs(self.to),
                self.stream.read_exact(&mut body),
            )
            .await
            .map_err(|_| "read timeout".to_string())?
            .map_err(|e| format!("read: {}", e))?;
        }
        Ok((header[0], body))
    }

    async fn write(&mut self, data: &[u8]) -> Result<(), String> {
        tokio::time::timeout(Duration::from_secs(self.to), self.stream.write_all(data))
            .await
            .map_err(|_| "write timeout".to_string())?
            .map_err(|e| format!("write: {}", e))
    }
}

fn startup_packet(user: &str, database: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&196_608u32.to_be_bytes()); // protocol 3.0
    for (key, value) in [
        ("user", user),
        ("database", database),
        ("application_name", "keystrike"),
        ("client_encoding", "UTF8"),
    ] {
        body.extend_from_slice(key.as_bytes());
        body.push(0);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);

    let mut packet = Vec::with_capacity(body.len() + 4);
    packet.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    packet.extend_from_slice(&body);
    packet
}

fn password_message(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 5);
    out.push(b'p');
    out.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Split a `KeyValue\0` list, used by the SASL mechanism advertisement.
fn read_cstrings(buf: &[u8]) -> Vec<String> {
    buf.split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).to_string())
        .collect()
}

fn error_text(body: &[u8]) -> String {
    // ErrorResponse is a sequence of (field-type byte, C string).
    let mut parts = Vec::new();
    let mut i = 0;
    while i < body.len() && body[i] != 0 {
        let field = body[i];
        i += 1;
        let start = i;
        while i < body.len() && body[i] != 0 {
            i += 1;
        }
        if field == b'M' || field == b'C' {
            parts.push(String::from_utf8_lossy(&body[start..i]).to_string());
        }
        if i < body.len() {
            i += 1;
        }
    }
    if parts.is_empty() {
        "authentication failed".to_string()
    } else {
        parts.join(": ")
    }
}

pub async fn auth(
    target: &str,
    port: u16,
    user: &str,
    pass: &str,
    to: u64,
) -> Result<bool, String> {
    let stream = tokio::time::timeout(
        Duration::from_secs(to),
        TcpStream::connect(format!("{}:{}", target, port)),
    )
    .await
    .map_err(|_| "connect timeout".to_string())?
    .map_err(|e| format!("connect: {}", e))?;
    let _ = stream.set_nodelay(true);

    let mut conn = Reader { stream, to };
    conn.write(&startup_packet(user, "postgres")).await?;

    loop {
        let (tag, body) = conn.message().await?;
        match tag {
            b'R' => {
                if body.len() < 4 {
                    return Err("short authentication request".into());
                }
                let subtype = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                match subtype {
                    0 => return Ok(true),
                    3 => {
                        let mut payload = pass.as_bytes().to_vec();
                        payload.push(0);
                        conn.write(&password_message(&payload)).await?;
                    }
                    5 => {
                        if body.len() < 8 {
                            return Err("short MD5 challenge".into());
                        }
                        let response = md5_password(user, pass, &body[4..8]);
                        let mut payload = response.into_bytes();
                        payload.push(0);
                        conn.write(&password_message(&payload)).await?;
                    }
                    10 => {
                        let mechanisms = read_cstrings(&body[4..]);
                        if !mechanisms.iter().any(|m| m == "SCRAM-SHA-256") {
                            return Err(format!(
                                "server offers no supported SASL mechanism ({:?})",
                                mechanisms
                            ));
                        }
                        scram(&mut conn, user, pass).await?;
                    }
                    other => {
                        return Err(format!("unsupported PostgreSQL auth method {}", other))
                    }
                }
            }
            b'E' => {
                let text = error_text(&body);
                // A wrong password is a denial, not a transport failure.
                let low = text.to_ascii_lowercase();
                if low.contains("password") || low.contains("authentication") || low.contains("role")
                {
                    return Ok(false);
                }
                return Err(format!("postgres: {}", text));
            }
            b'Z' => return Ok(false),
            // ParameterStatus / BackendKeyData / NoticeResponse — keep reading.
            _ => continue,
        }
    }
}

/// SCRAM-SHA-256 exchange. Runs to the server-final message and verifies the
/// server signature, so a hostile or broken server cannot fake a success.
async fn scram(conn: &mut Reader, user: &str, pass: &str) -> Result<(), String> {
    let nonce_bytes: [u8; 18] = rand::random();
    let nonce = base64::engine::general_purpose::STANDARD.encode(nonce_bytes);
    let client_first_bare = format!("n=,r={}", nonce);
    let client_first = format!("n,,{}", client_first_bare);

    let mut payload = b"SCRAM-SHA-256\0".to_vec();
    payload.extend_from_slice(&(client_first.len() as u32).to_be_bytes());
    payload.extend_from_slice(client_first.as_bytes());
    conn.write(&password_message(&payload)).await?;

    let (tag, body) = conn.message().await?;
    if tag == b'E' {
        return Err(format!("postgres: {}", error_text(&body)));
    }
    if tag != b'R' || body.len() < 4 {
        return Err("expected SASLContinue".into());
    }
    let subtype = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    if subtype != 11 {
        return Err(format!("unexpected SASL step {}", subtype));
    }

    let server_first = String::from_utf8_lossy(&body[4..]).to_string();
    let mut server_nonce = String::new();
    let mut salt = Vec::new();
    let mut iterations = 0u32;
    for field in server_first.split(',') {
        if let Some(v) = field.strip_prefix("r=") {
            server_nonce = v.to_string();
        } else if let Some(v) = field.strip_prefix("s=") {
            salt = base64::engine::general_purpose::STANDARD
                .decode(v)
                .map_err(|e| format!("bad salt: {}", e))?;
        } else if let Some(v) = field.strip_prefix("i=") {
            iterations = v.parse().map_err(|_| "bad iteration count".to_string())?;
        }
    }
    if iterations == 0 || salt.is_empty() {
        return Err("incomplete SCRAM challenge".into());
    }
    if !server_nonce.starts_with(&nonce) {
        return Err("server nonce does not extend the client nonce".into());
    }

    let salted = pbkdf2_sha256(pass.as_bytes(), &salt, iterations);
    let client_key = hmac_sha256(&salted, b"Client Key");
    let stored_key = sha256(&client_key);
    let client_final_without_proof = format!("c=biws,r={}", server_nonce);
    let auth_message = format!(
        "{},{},{}",
        client_first_bare, server_first, client_final_without_proof
    );
    let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
    let proof: Vec<u8> = client_key
        .iter()
        .zip(client_signature.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    let proof_b64 = base64::engine::general_purpose::STANDARD.encode(proof);
    let client_final = format!("{},p={}", client_final_without_proof, proof_b64);

    conn.write(&password_message(client_final.as_bytes())).await?;

    let (tag, body) = conn.message().await?;
    if tag == b'E' {
        // A SCRAM failure here is an invalid password.
        return Err(format!("__denied__{}", error_text(&body)));
    }
    if tag != b'R' || body.len() < 4 {
        return Err("expected SASLFinal".into());
    }
    let subtype = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    if subtype != 12 {
        return Err(format!("unexpected SASL final step {}", subtype));
    }

    let server_final = String::from_utf8_lossy(&body[4..]).to_string();
    let mut server_signature = String::new();
    let mut server_error = String::new();
    for field in server_final.split(',') {
        if let Some(v) = field.strip_prefix("v=") {
            server_signature = v.to_string();
        } else if let Some(v) = field.strip_prefix("e=") {
            server_error = v.to_string();
        }
    }
    if !server_error.is_empty() {
        return Err(format!("__denied__{}", server_error));
    }
    if server_signature.is_empty() {
        return Err("server sent no SCRAM signature".into());
    }

    let server_key = hmac_sha256(&salted, b"Server Key");
    let expected = hmac_sha256(&server_key, auth_message.as_bytes());
    let expected_b64 = base64::engine::general_purpose::STANDARD.encode(expected);
    if expected_b64 != server_signature {
        return Err("SCRAM server signature mismatch".into());
    }
    Ok(())
}
