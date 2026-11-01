//! RDP authentication via CredSSP / NLA.
//!
//! The old implementation returned "RDP requires external tool (Hydra)", which
//! is a hole in the protocol table. NLA is a real, documented exchange and this
//! performs it end to end:
//!
//!   TCP → TPKT + X.224 Connection Request (RDP_NEG_REQ, HYBRID) →
//!   X.224 Connection Confirm → TLS → TSRequest/NegoData carrying a SPNEGO
//!   NegTokenInit with NTLMSSP NEGOTIATE → server's NTLMSSP CHALLENGE →
//!   SPNEGO NegTokenResp with NTLMSSP AUTHENTICATE (NTLMv2) → errorCode.
//!
//! `errorCode == 0` means the credentials were accepted. A non-zero errorCode
//! is a refusal; `STATUS_LOGON_FAILURE` is the ordinary wrong-password answer.
//!
//! Servers that answer the connection request with plain RDP security (no NLA)
//! are reported as such — there is no password check to perform over TLS there,
//! and pretending otherwise would produce a false verdict.

use crate::core::ntlm;
use crate::core::tls;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::client::TlsStream;

const PROTOCOL_SSL: u32 = 0x0000_0001;
const PROTOCOL_HYBRID: u32 = 0x0000_0002;

const STATUS_SUCCESS: u32 = 0x0000_0000;

// ─────────────────────────── DER ───────────────────────────

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else {
        vec![0x82, ((len >> 8) & 0xFF) as u8, (len & 0xFF) as u8]
    }
}

fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 4);
    out.push(tag);
    out.extend(der_len(body.len()));
    out.extend_from_slice(body);
    out
}

fn der_int(value: u8) -> Vec<u8> {
    der(0x02, &[value])
}

/// `[n]` constructed.
fn der_ctx(n: u8, body: &[u8]) -> Vec<u8> {
    der(0xA0 + n, body)
}

/// OID 1.3.6.1.5.5.2 — SPNEGO.
fn oid_spnego() -> Vec<u8> {
    der(0x06, &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x02])
}

/// OID 1.3.6.1.4.1.311.2.2.10 — NTLMSSP.
fn oid_ntlmssp() -> Vec<u8> {
    der(
        0x06,
        &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02],
    )
}

/// Full GSS-API SPNEGO NegTokenInit wrapping an NTLMSSP NEGOTIATE.
fn spnego_init(ntlm_token: &[u8]) -> Vec<u8> {
    let mech = der(0x30, &oid_ntlmssp());
    let mech_types = der_ctx(0, &mech);
    let mech_token = der_ctx(2, &der(0x04, ntlm_token));
    let mut init_body = mech_types;
    init_body.extend_from_slice(&mech_token);
    let neg_token_init = der(0x30, &init_body);
    let explicit = der_ctx(0, &neg_token_init);

    let mut gss_body = oid_spnego();
    gss_body.extend_from_slice(&explicit);
    // [APPLICATION 0] is 0x60.
    der(0x60, &gss_body)
}

/// SPNEGO NegTokenResp wrapping an NTLMSSP AUTHENTICATE.
fn spnego_resp(ntlm_token: &[u8]) -> Vec<u8> {
    let response_token = der_ctx(2, &der(0x04, ntlm_token));
    let neg_token_resp = der(0x30, &response_token);
    // [1] CHOICE selects negTokenResp.
    der(0xA1, &neg_token_resp)
}

/// TSRequest ::= SEQUENCE { version [0] INTEGER, negoTokens [1] NegoData }
fn ts_request(version: u8, nego_token: &[u8]) -> Vec<u8> {
    let version_field = der_ctx(0, &der_int(version));
    let inner = der_ctx(0, &der(0x04, nego_token));
    let nego_data = der(0x30, &inner);
    let nego_tokens = der_ctx(1, &nego_data);

    let mut body = version_field;
    body.extend_from_slice(&nego_tokens);
    der(0x30, &body)
}

/// Walk the DER looking for the first primitive OCTET STRING that contains the
/// NTLMSSP signature and return the token from there. Servers wrap the token in
/// SPNEGO whose exact shape varies (some omit negState, some add MIC), so
/// locating the signature is more reliable than assuming a fixed layout.
fn extract_ntlm_token(buf: &[u8]) -> Option<Vec<u8>> {
    let marker = b"NTLMSSP\0";
    let pos = buf.windows(marker.len()).position(|w| w == marker)?;
    Some(buf[pos..].to_vec())
}

/// Read the integer carried by `[4] errorCode` in a TSRequest, if present.
fn read_error_code(buf: &[u8]) -> Option<u32> {
    let mut i = 0;
    while i + 1 < buf.len() {
        if buf[i] == 0xA4 {
            let (len, mut p) = read_der_len(buf, i + 1)?;
            if p + len > buf.len() {
                return None;
            }
            if buf[p] == 0x02 {
                let (ilen, ip) = read_der_len(buf, p + 1)?;
                if ip + ilen > buf.len() || ilen == 0 || ilen > 8 {
                    return None;
                }
                // DER pads a positive integer with a leading zero when the top
                // bit would otherwise read as a sign bit; accumulate and cast.
                let mut value: u64 = 0;
                for byte in &buf[ip..ip + ilen] {
                    value = (value << 8) | *byte as u64;
                }
                return Some(value as u32);
            }
            p += len;
            i = p;
            continue;
        }
        i += 1;
    }
    None
}

fn read_der_len(buf: &[u8], pos: usize) -> Option<(usize, usize)> {
    let first = *buf.get(pos)?;
    if first & 0x80 == 0 {
        Some((first as usize, pos + 1))
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 2 || pos + 1 + n > buf.len() {
            return None;
        }
        let mut value = 0usize;
        for i in 0..n {
            value = (value << 8) | buf[pos + 1 + i] as usize;
        }
        Some((value, pos + 1 + n))
    }
}

// ─────────────────────────── TPKT ───────────────────────────

fn tpkt(payload: &[u8]) -> Vec<u8> {
    let total = payload.len() + 4;
    let mut out = Vec::with_capacity(total);
    out.push(0x03);
    out.push(0x00);
    out.push(((total >> 8) & 0xFF) as u8);
    out.push((total & 0xFF) as u8);
    out.extend_from_slice(payload);
    out
}

fn x224_connection_request() -> Vec<u8> {
    // LI covers the six fixed X.224 bytes that follow it. The RDP negotiation
    // block is appended after the class byte and is not counted by LI.
    let mut out = vec![0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00];
    // RDP_NEG_REQ: type 1, flags 0, length 8, requestedProtocols.
    out.extend_from_slice(&[0x01, 0x00, 0x08, 0x00]);
    out.extend_from_slice(&(PROTOCOL_SSL | PROTOCOL_HYBRID).to_le_bytes());
    out
}

/// Read one TPKT frame from the stream.
async fn read_tpkt<S>(stream: &mut S, to: u64) -> Result<Vec<u8>, String>
where
    S: AsyncReadExt + Unpin,
{
    let mut header = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(to), stream.read_exact(&mut header))
        .await
        .map_err(|_| "read timeout".to_string())?
        .map_err(|e| format!("read: {}", e))?;
    if header[0] != 0x03 {
        return Err(format!("not a TPKT frame (version 0x{:02X})", header[0]));
    }
    let len = u16::from_be_bytes([header[2], header[3]]) as usize;
    if !(7..=1_048_576).contains(&len) {
        return Err(format!("bad TPKT length {}", len));
    }
    let mut payload = vec![0u8; len - 4];
    tokio::time::timeout(Duration::from_secs(to), stream.read_exact(&mut payload))
        .await
        .map_err(|_| "read timeout".to_string())?
        .map_err(|e| format!("read: {}", e))?;
    Ok(payload)
}

async fn write_tpkt<S>(stream: &mut S, payload: &[u8], to: u64) -> Result<(), String>
where
    S: AsyncWriteExt + Unpin,
{
    let frame = tpkt(payload);
    tokio::time::timeout(Duration::from_secs(to), stream.write_all(&frame))
        .await
        .map_err(|_| "write timeout".to_string())?
        .map_err(|e| format!("write: {}", e))
}

/// Parse the X.224 Connection Confirm and return the selected protocol.
fn selected_protocol(payload: &[u8]) -> Result<u32, String> {
    if payload.len() < 7 {
        return Err("short X.224 confirm".into());
    }
    if payload[1] != 0xD0 {
        // 0x0F is Connection Confirm for RDP; 0xD0 is the code point.
        if payload[1] != 0x0F {
            return Err(format!("unexpected X.224 code 0x{:02X}", payload[1]));
        }
    }
    // RDP_NEG_RSP starts after the fixed X.224 part.
    let mut i = 2 + 5; // dst-ref(2) + src-ref(2) + class(1) after LI+code
    while i + 8 <= payload.len() {
        let kind = payload[i];
        let length = u16::from_le_bytes([payload[i + 2], payload[i + 3]]) as usize;
        if length < 8 || i + length > payload.len() {
            break;
        }
        if kind == 0x02 {
            return Ok(u32::from_le_bytes([
                payload[i + 4],
                payload[i + 5],
                payload[i + 6],
                payload[i + 7],
            ]));
        }
        if kind == 0x03 {
            // RDP_NEG_FAILURE.
            return Err(format!(
                "server refused the security negotiation (code 0x{:08X})",
                u32::from_le_bytes([
                    payload[i + 4],
                    payload[i + 5],
                    payload[i + 6],
                    payload[i + 7]
                ])
            ));
        }
        i += length;
    }
    // No negotiation block: the server selected plain RDP security.
    Ok(0)
}

async fn credssp(
    stream: &mut TlsStream<tokio::net::TcpStream>,
    user: &str,
    pass: &str,
    to: u64,
) -> Result<bool, String> {
    let (username, domain) = ntlm::split_identity(user);

    // Round 1 — NTLMSSP NEGOTIATE inside SPNEGO inside TSRequest.
    let type1 = ntlm::build_type1(&domain);
    let request = ts_request(3, &spnego_init(&type1));
    write_tpkt(stream, &request, to).await?;

    let reply = read_tpkt(stream, to).await?;
    if let Some(code) = read_error_code(&reply) {
        if code != STATUS_SUCCESS {
            return Err(format!("CredSSP error before challenge: 0x{:08X}", code));
        }
    }
    let challenge_token = extract_ntlm_token(&reply)
        .ok_or_else(|| "CredSSP reply carried no NTLMSSP challenge".to_string())?;
    let challenge = ntlm::parse_type2(&challenge_token)?;

    // Round 2 — NTLMSSP AUTHENTICATE with the NTLMv2 response.
    let type3 = ntlm::build_type3(&username, &domain, pass, &challenge);
    let request = ts_request(3, &spnego_resp(&type3));
    write_tpkt(stream, &request, to).await?;

    let reply = read_tpkt(stream, to).await?;
    match read_error_code(&reply) {
        Some(STATUS_SUCCESS) => Ok(true),
        // Every non-zero errorCode is a refusal: STATUS_LOGON_FAILURE is the
        // ordinary wrong-password answer, and the rest mean the account or the
        // policy rejected the logon. None of them is a transport failure.
        Some(_) => Ok(false),
        None => {
            // No errorCode means the server sent more negotiation data rather
            // than a verdict — a broken or non-standard peer.
            Err("CredSSP reply carried no errorCode".into())
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
    let mut stream = tokio::time::timeout(
        Duration::from_secs(to),
        tokio::net::TcpStream::connect(format!("{}:{}", target, port)),
    )
    .await
    .map_err(|_| "connect timeout".to_string())?
    .map_err(|e| format!("connect: {}", e))?;
    let _ = stream.set_nodelay(true);

    write_tpkt(&mut stream, &x224_connection_request(), to).await?;
    let confirm = read_tpkt(&mut stream, to).await?;
    let selected = selected_protocol(&confirm)?;

    if selected & PROTOCOL_HYBRID == 0 {
        if selected & PROTOCOL_SSL != 0 {
            return Err(
                "server selected plain TLS RDP security, not NLA — no password check is possible"
                    .into(),
            );
        }
        return Err(format!(
            "server selected RDP security 0x{:08X}; NLA is not enabled",
            selected
        ));
    }

    let mut tls_stream = tls::wrap(stream, target, to).await?;
    credssp(&mut tls_stream, user, pass, to).await
}
