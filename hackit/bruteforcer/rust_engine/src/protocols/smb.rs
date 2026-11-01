//! SMB2/3 authentication with NTLMv2.
//!
//! The previous implementation hand-rolled a session-setup packet with wrong
//! offsets and treated `STATUS_ACCESS_DENIED` as a success — it could not
//! authenticate anything, and it reported failures as wins.
//!
//! This speaks the real exchange:
//!   NEGOTIATE → SESSION_SETUP(NTLMSSP NEGOTIATE) →
//!   SESSION_SETUP(NTLMSSP AUTHENTICATE with NTLMv2 response) → verdict
//!
//! `STATUS_SUCCESS` is a valid credential. `STATUS_LOGON_FAILURE` and
//! `STATUS_ACCESS_DENIED` are both refusals: the account exists but the password
//! did not open it, or it is not permitted to log on. Everything else is a
//! transport/protocol problem and is surfaced as such.

use hmac::{Hmac, Mac};
use md4::Md4;
use md5::{Digest as _, Md5};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

type HmacMd5 = Hmac<Md5>;

const SMB2_NEGOTIATE: u16 = 0x0000;
const SMB2_SESSION_SETUP: u16 = 0x0001;

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_MORE_PROCESSING: u32 = 0xC000_0016;
const STATUS_LOGON_FAILURE: u32 = 0xC000_006D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_ACCOUNT_DISABLED: u32 = 0xC000_0072;
const STATUS_ACCOUNT_LOCKED_OUT: u32 = 0xC000_0234;
const STATUS_PASSWORD_EXPIRED: u32 = 0xC000_0071;

const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
const NEGOTIATE_OEM: u32 = 0x0000_0002;
const NEGOTIATE_NTLM: u32 = 0x0000_0200;
const NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
const NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
const NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
const NEGOTIATE_128: u32 = 0x2000_0000;
const NEGOTIATE_56: u32 = 0x8000_0000;

fn utf16le(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

fn nt_hash(password: &str) -> [u8; 16] {
    let mut hasher = Md4::new();
    hasher.update(utf16le(password));
    let mut out = [0u8; 16];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = HmacMd5::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

fn ntlmv2_hash(user: &str, domain: &str, password: &str) -> [u8; 16] {
    let identity = utf16le(&format!("{}{}", user.to_uppercase(), domain));
    hmac_md5(&nt_hash(password), &identity)
}

/// 100-nanosecond ticks since 1601-01-01, as NTLM's AV timestamp expects.
fn filetime_now() -> u64 {
    const EPOCH_DIFF: u64 = 11_644_473_600;
    let since_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    (since_unix + EPOCH_DIFF) * 10_000_000
}

/// Split `DOMAIN\user` or `user@domain` into its parts. A bare name is a local
/// account and uses an empty domain, which is what Windows expects.
fn split_identity(user: &str) -> (String, String) {
    if let Some((domain, name)) = user.split_once('\\') {
        (name.to_string(), domain.to_string())
    } else if let Some((name, domain)) = user.split_once('@') {
        (name.to_string(), domain.to_string())
    } else {
        (user.to_string(), String::new())
    }
}

fn build_type1(domain: &str) -> Vec<u8> {
    let flags = NEGOTIATE_UNICODE
        | NEGOTIATE_OEM
        | NEGOTIATE_NTLM
        | NEGOTIATE_ALWAYS_SIGN
        | NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NEGOTIATE_TARGET_INFO
        | NEGOTIATE_128
        | NEGOTIATE_56;
    let domain_bytes = utf16le(domain);
    let payload_offset = 32u32;

    let mut out = Vec::with_capacity(32 + domain_bytes.len());
    out.extend_from_slice(b"NTLMSSP\0");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&(domain_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(&(domain_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(&payload_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // workstation len
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&payload_offset.to_le_bytes());
    out.extend_from_slice(&domain_bytes);
    out
}

struct Type2 {
    server_challenge: [u8; 8],
    target_info: Vec<u8>,
    flags: u32,
}

fn parse_type2(token: &[u8]) -> Result<Type2, String> {
    if token.len() < 48 || &token[..8] != b"NTLMSSP\0" {
        return Err("not an NTLMSSP CHALLENGE".into());
    }
    let message_type = u32::from_le_bytes(token[8..12].try_into().unwrap());
    if message_type != 2 {
        return Err(format!("expected NTLMSSP type 2, got {}", message_type));
    }
    let flags = u32::from_le_bytes(token[20..24].try_into().unwrap());
    let mut challenge = [0u8; 8];
    challenge.copy_from_slice(&token[24..32]);

    let mut target_info = Vec::new();
    if token.len() >= 48 {
        let len = u16::from_le_bytes(token[40..42].try_into().unwrap()) as usize;
        let offset = u32::from_le_bytes(token[44..48].try_into().unwrap()) as usize;
        if len > 0 && offset + len <= token.len() {
            target_info = token[offset..offset + len].to_vec();
        }
    }

    Ok(Type2 {
        server_challenge: challenge,
        target_info,
        flags,
    })
}

fn build_type3(
    user: &str,
    domain: &str,
    password: &str,
    challenge: &Type2,
) -> Vec<u8> {
    let ntlmv2 = ntlmv2_hash(user, domain, password);
    let client_challenge: [u8; 8] = rand::random();

    // The blob echoes the server's AV pairs, stamps the time, and pins the
    // client nonce. This is the structure every NTLMv2 client sends.
    let mut blob = Vec::new();
    blob.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]); // blob version
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // reserved
    blob.extend_from_slice(&filetime_now().to_le_bytes());
    blob.extend_from_slice(&client_challenge);
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // reserved
    blob.extend_from_slice(&challenge.target_info);
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // terminator

    let mut seeded = Vec::with_capacity(8 + blob.len());
    seeded.extend_from_slice(&challenge.server_challenge);
    seeded.extend_from_slice(&blob);
    let proof = hmac_md5(&ntlmv2, &seeded);

    let mut nt_response = Vec::with_capacity(16 + blob.len());
    nt_response.extend_from_slice(&proof);
    nt_response.extend_from_slice(&blob);

    let mut lm_seeded = Vec::with_capacity(16);
    lm_seeded.extend_from_slice(&challenge.server_challenge);
    lm_seeded.extend_from_slice(&client_challenge);
    let lm_proof = hmac_md5(&ntlmv2, &lm_seeded);
    let mut lm_response = Vec::with_capacity(24);
    lm_response.extend_from_slice(&lm_proof);
    lm_response.extend_from_slice(&client_challenge);

    let domain_bytes = utf16le(domain);
    let user_bytes = utf16le(user);
    let workstation = utf16le("KEYSTRIKE");

    let flags = (challenge.flags
        & (NEGOTIATE_UNICODE
            | NEGOTIATE_NTLM
            | NEGOTIATE_ALWAYS_SIGN
            | NEGOTIATE_EXTENDED_SESSIONSECURITY
            | NEGOTIATE_128
            | NEGOTIATE_56))
        | NEGOTIATE_UNICODE;

    let header_len = 64usize;
    let mut out = Vec::with_capacity(header_len + nt_response.len() + domain_bytes.len() + user_bytes.len());
    out.extend_from_slice(b"NTLMSSP\0");
    out.extend_from_slice(&3u32.to_le_bytes());

    let mut offset = header_len as u32;
    let mut push_field = |out: &mut Vec<u8>, data: &[u8], offset: &mut u32| {
        out.extend_from_slice(&(data.len() as u16).to_le_bytes());
        out.extend_from_slice(&(data.len() as u16).to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        *offset += data.len() as u32;
    };

    push_field(&mut out, &lm_response, &mut offset);
    push_field(&mut out, &nt_response, &mut offset);
    push_field(&mut out, &domain_bytes, &mut offset);
    push_field(&mut out, &user_bytes, &mut offset);
    push_field(&mut out, &workstation, &mut offset);
    // Session key: empty.
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());

    out.extend_from_slice(&lm_response);
    out.extend_from_slice(&nt_response);
    out.extend_from_slice(&domain_bytes);
    out.extend_from_slice(&user_bytes);
    out.extend_from_slice(&workstation);
    out
}

fn smb2_header(command: u16, message_id: u64, session_id: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&[0xFE, b'S', b'M', b'B']);
    out.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    out.extend_from_slice(&1u16.to_le_bytes()); // CreditCharge
    out.extend_from_slice(&0u32.to_le_bytes()); // Status / ChannelSequence
    out.extend_from_slice(&command.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // CreditRequest
    out.extend_from_slice(&0u32.to_le_bytes()); // Flags
    out.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    out.extend_from_slice(&message_id.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // ProcessId
    out.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    out.extend_from_slice(&session_id.to_le_bytes());
    out.extend_from_slice(&[0u8; 16]); // Signature
    out
}

fn nbss(payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut out = Vec::with_capacity(4 + len);
    out.push(0x00);
    out.push(((len >> 16) & 0xFF) as u8);
    out.push(((len >> 8) & 0xFF) as u8);
    out.push((len & 0xFF) as u8);
    out.extend_from_slice(payload);
    out
}

fn build_negotiate() -> Vec<u8> {
    let dialects: [u16; 5] = [0x0311, 0x0302, 0x0300, 0x0210, 0x0202];
    let mut body = Vec::with_capacity(36 + dialects.len() * 2);
    body.extend_from_slice(&36u16.to_le_bytes()); // StructureSize
    body.extend_from_slice(&(dialects.len() as u16).to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode: signing enabled
    body.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    body.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    body.extend_from_slice(&rand::random::<[u8; 16]>()); // ClientGuid
    body.extend_from_slice(&0u64.to_le_bytes()); // NegotiateContextOffset
    body.extend_from_slice(&0u16.to_le_bytes()); // NegotiateContextCount
    body.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    for dialect in dialects {
        body.extend_from_slice(&dialect.to_le_bytes());
    }

    let mut packet = smb2_header(SMB2_NEGOTIATE, 0, 0);
    packet.extend_from_slice(&body);
    nbss(&packet)
}

fn build_session_setup(token: &[u8], message_id: u64, session_id: u64) -> Vec<u8> {
    let mut body = Vec::with_capacity(24 + token.len());
    body.extend_from_slice(&25u16.to_le_bytes()); // StructureSize
    body.push(0); // Flags
    body.push(1); // SecurityMode: signing enabled
    body.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    body.extend_from_slice(&0u32.to_le_bytes()); // Channel
    // SecurityBufferOffset is measured from the start of the SMB2 header.
    body.extend_from_slice(&(64u16 + 24u16).to_le_bytes());
    body.extend_from_slice(&(token.len() as u16).to_le_bytes());
    body.extend_from_slice(&0u64.to_le_bytes()); // PreviousSessionId
    body.extend_from_slice(token);

    let mut packet = smb2_header(SMB2_SESSION_SETUP, message_id, session_id);
    packet.extend_from_slice(&body);
    nbss(&packet)
}

struct Smb2Reply {
    status: u32,
    session_id: u64,
    body: Vec<u8>,
}

async fn exchange(stream: &mut TcpStream, request: &[u8], to: u64) -> Result<Smb2Reply, String> {
    tokio::time::timeout(Duration::from_secs(to), stream.write_all(request))
        .await
        .map_err(|_| "write timeout".to_string())?
        .map_err(|e| format!("write: {}", e))?;

    let mut nb = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(to), stream.read_exact(&mut nb))
        .await
        .map_err(|_| "read timeout".to_string())?
        .map_err(|e| format!("read: {}", e))?;
    let len = ((nb[1] as usize) << 16) | ((nb[2] as usize) << 8) | nb[3] as usize;
    if !(64..=16 * 1024 * 1024).contains(&len) {
        return Err(format!("bad SMB2 frame length {}", len));
    }
    let mut payload = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(to), stream.read_exact(&mut payload))
        .await
        .map_err(|_| "read timeout".to_string())?
        .map_err(|e| format!("read: {}", e))?;

    if payload.len() < 64 || &payload[..4] != [0xFE, b'S', b'M', b'B'] {
        return Err("not an SMB2 frame".into());
    }
    let status = u32::from_le_bytes(payload[8..12].try_into().unwrap());
    let session_id = u64::from_le_bytes(payload[42..50].try_into().unwrap());
    Ok(Smb2Reply {
        status,
        session_id,
        body: payload[64..].to_vec(),
    })
}

/// The security buffer of a SESSION_SETUP response, trimmed to the raw NTLMSSP
/// token (servers wrap it in SPNEGO; we only need the token inside).
fn extract_ntlmssp(body: &[u8]) -> Option<Vec<u8>> {
    if body.len() < 8 {
        return None;
    }
    let offset = u16::from_le_bytes(body[4..6].try_into().ok()?) as usize;
    let len = u16::from_le_bytes(body[6..8].try_into().ok()?) as usize;
    // Offset is from the start of the SMB2 header; the body slice starts at 64.
    let start = offset.checked_sub(64)?;
    if start + len > body.len() {
        return None;
    }
    let buffer = &body[start..start + len];
    let marker = b"NTLMSSP\0";
    let pos = buffer
        .windows(marker.len())
        .position(|window| window == marker)?;
    Some(buffer[pos..].to_vec())
}

pub async fn auth(
    target: &str,
    port: u16,
    user: &str,
    pass: &str,
    to: u64,
) -> Result<bool, String> {
    let (username, domain) = split_identity(user);

    let mut stream = tokio::time::timeout(
        Duration::from_secs(to),
        TcpStream::connect(format!("{}:{}", target, port)),
    )
    .await
    .map_err(|_| "connect timeout".to_string())?
    .map_err(|e| format!("connect: {}", e))?;
    let _ = stream.set_nodelay(true);

    // NEGOTIATE
    let negotiate = build_negotiate();
    let reply = exchange(&mut stream, &negotiate, to).await?;
    if reply.status != STATUS_SUCCESS {
        return Err(format!("SMB2 negotiate failed: 0x{:08X}", reply.status));
    }

    // SESSION_SETUP — NTLMSSP NEGOTIATE
    let type1 = build_type1(&domain);
    let reply = exchange(&mut stream, &build_session_setup(&type1, 1, 0), to).await?;
    if reply.status != STATUS_MORE_PROCESSING {
        if reply.status == STATUS_SUCCESS {
            // Guest/anonymous was accepted without credentials.
            return Err("SMB server allows anonymous session setup".into());
        }
        return Err(format!("SMB2 session setup rejected: 0x{:08X}", reply.status));
    }

    let challenge_token = extract_ntlmssp(&reply.body)
        .ok_or_else(|| "SMB2 challenge carried no NTLMSSP token".to_string())?;
    let challenge = parse_type2(&challenge_token)?;

    // SESSION_SETUP — NTLMSSP AUTHENTICATE
    let type3 = build_type3(&username, &domain, pass, &challenge);
    let reply = exchange(
        &mut stream,
        &build_session_setup(&type3, 2, reply.session_id),
        to,
    )
    .await?;

    match reply.status {
        STATUS_SUCCESS => Ok(true),
        STATUS_LOGON_FAILURE | STATUS_ACCESS_DENIED => Ok(false),
        STATUS_ACCOUNT_DISABLED | STATUS_ACCOUNT_LOCKED_OUT | STATUS_PASSWORD_EXPIRED => {
            // The credential is correct but the account cannot log in. Reporting
            // it as a hit would be a lie; reporting it as a miss hides a real
            // finding. Surface it as a transport-level note.
            Err(format!(
                "account rejected after authentication: 0x{:08X}",
                reply.status
            ))
        }
        other => Err(format!("SMB2 session setup failed: 0x{:08X}", other)),
    }
}
