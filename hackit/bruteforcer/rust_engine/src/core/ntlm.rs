//! NTLMSSP message construction and NTLMv2 response computation.
//!
//! Shared by SMB2 session setup and RDP/CredSSP, which perform the same
//! three-message exchange with a different outer wrapper. Keeping one copy
//! means a fix to the AV-pair blob or the LM response lands in both.
//!
//! The response is genuine NTLMv2: `HMAC-MD5(NTLMv2Hash, server_challenge ||
//! blob)` where the blob carries a fresh client nonce, a filetime timestamp,
//! and the server's target-info AV pairs verbatim. Servers reject anything
//! else, so there is no shortcut here.

use hmac::{Hmac, Mac};
use md4::Md4;
use md5::{Digest as _, Md5};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacMd5 = Hmac<Md5>;

pub const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
pub const NEGOTIATE_OEM: u32 = 0x0000_0002;
pub const NEGOTIATE_NTLM: u32 = 0x0000_0200;
pub const NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
pub const NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
pub const NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
pub const NEGOTIATE_128: u32 = 0x2000_0000;
pub const NEGOTIATE_56: u32 = 0x8000_0000;

pub fn utf16le(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

pub fn nt_hash(password: &str) -> [u8; 16] {
    let mut hasher = Md4::new();
    hasher.update(utf16le(password));
    let mut out = [0u8; 16];
    out.copy_from_slice(&hasher.finalize());
    out
}

pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = HmacMd5::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

pub fn ntlmv2_hash(user: &str, domain: &str, password: &str) -> [u8; 16] {
    let identity = utf16le(&format!("{}{}", user.to_uppercase(), domain));
    hmac_md5(&nt_hash(password), &identity)
}

/// 100-nanosecond ticks since 1601-01-01, as NTLM's AV timestamp expects.
pub fn filetime_now() -> u64 {
    const EPOCH_DIFF: u64 = 11_644_473_600;
    let since_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    (since_unix + EPOCH_DIFF) * 10_000_000
}

/// Split `DOMAIN\user` or `user@domain` into its parts. A bare name is a local
/// account and uses an empty domain, which is what Windows expects.
pub fn split_identity(user: &str) -> (String, String) {
    if let Some((domain, name)) = user.split_once('\\') {
        (name.to_string(), domain.to_string())
    } else if let Some((name, domain)) = user.split_once('@') {
        (name.to_string(), domain.to_string())
    } else {
        (user.to_string(), String::new())
    }
}

fn default_flags() -> u32 {
    NEGOTIATE_UNICODE
        | NEGOTIATE_OEM
        | NEGOTIATE_NTLM
        | NEGOTIATE_ALWAYS_SIGN
        | NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NEGOTIATE_TARGET_INFO
        | NEGOTIATE_128
        | NEGOTIATE_56
}

/// NTLMSSP NEGOTIATE (type 1).
pub fn build_type1(domain: &str) -> Vec<u8> {
    let flags = default_flags();
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

pub struct Type2 {
    pub server_challenge: [u8; 8],
    pub target_info: Vec<u8>,
    pub flags: u32,
}

/// NTLMSSP CHALLENGE (type 2). Accepts both the bare token and a token with a
/// trailing MIC, since some servers append one.
pub fn parse_type2(token: &[u8]) -> Result<Type2, String> {
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
    let len = u16::from_le_bytes(token[40..42].try_into().unwrap()) as usize;
    let offset = u32::from_le_bytes(token[44..48].try_into().unwrap()) as usize;
    if len > 0 && offset + len <= token.len() {
        target_info = token[offset..offset + len].to_vec();
    }

    Ok(Type2 {
        server_challenge: challenge,
        target_info,
        flags,
    })
}

/// NTLMSSP AUTHENTICATE (type 3) carrying an NTLMv2 response.
pub fn build_type3(user: &str, domain: &str, password: &str, challenge: &Type2) -> Vec<u8> {
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
    let mut out =
        Vec::with_capacity(header_len + nt_response.len() + domain_bytes.len() + user_bytes.len());
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Microsoft's documented NT hash for "Password".
    #[test]
    fn nt_hash_known_answer() {
        assert_eq!(
            nt_hash("Password"),
            [
                0xa4, 0xf4, 0x9c, 0x40, 0x65, 0x10, 0xbd, 0xca, 0xb6, 0x82, 0x4e, 0xe7, 0xc3,
                0x0f, 0xd8, 0x52
            ]
        );
    }

    #[test]
    fn type3_layout_is_consistent() {
        let type2 = Type2 {
            server_challenge: [1, 2, 3, 4, 5, 6, 7, 8],
            target_info: vec![2, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            flags: default_flags(),
        };
        let token = build_type3("user", "DOMAIN", "pass", &type2);
        assert_eq!(&token[..8], b"NTLMSSP\0");
        assert_eq!(u32::from_le_bytes(token[8..12].try_into().unwrap()), 3);
        // NT response field points inside the buffer.
        let nt_len = u16::from_le_bytes(token[20..22].try_into().unwrap()) as usize;
        let nt_off = u32::from_le_bytes(token[24..28].try_into().unwrap()) as usize;
        assert!(nt_off + nt_len <= token.len());
        assert!(nt_len > 16);
    }
}
