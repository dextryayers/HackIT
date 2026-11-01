//! SNMP community-string authentication.
//!
//! The "username" field is unused — SNMPv1/v2c authenticate with a shared
//! community string, which the brute forcer carries in the password slot.
//!
//! Success is not "a packet came back". A UDP agent answers with a BER-encoded
//! `GetResponse` whose request-id matches ours; anything else (a trap, a
//! malformed echo, an ICMP unreachable surfacing as a read error) is noise.
//! The previous implementation tested `buf[0] == 0x30 && last == 0x00`, which
//! is true of almost every BER message ever sent.

use rand::Rng;
use std::time::Duration;
use tokio::net::UdpSocket;

const TAG_SEQUENCE: u8 = 0x30;
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_GET_REQUEST: u8 = 0xA0;
const TAG_GET_RESPONSE: u8 = 0xA2;

fn read_tlv<'a>(buf: &'a [u8], pos: &mut usize) -> Option<(u8, &'a [u8])> {
    if *pos + 2 > buf.len() {
        return None;
    }
    let tag = buf[*pos];
    let first_len = buf[*pos + 1] as usize;
    *pos += 2;
    let len = if first_len & 0x80 == 0 {
        first_len
    } else {
        let n = first_len & 0x7f;
        if n == 0 || n > 4 || *pos + n > buf.len() {
            return None;
        }
        let mut value = 0usize;
        for _ in 0..n {
            value = (value << 8) | buf[*pos] as usize;
            *pos += 1;
        }
        value
    };
    if *pos + len > buf.len() {
        return None;
    }
    let value = &buf[*pos..*pos + len];
    *pos += len;
    Some((tag, value))
}

fn encode_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let mut bytes = Vec::new();
        let mut l = len;
        while l > 0 {
            bytes.push((l & 0xFF) as u8);
            l >>= 8;
        }
        bytes.reverse();
        let mut out = vec![0x80 | bytes.len() as u8];
        out.extend(bytes);
        out
    }
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(encode_len(value.len()));
    out.extend_from_slice(value);
    out
}

fn encode_oid(oid: &[u32]) -> Vec<u8> {
    let mut body = Vec::new();
    if oid.len() >= 2 {
        body.push((oid[0] * 40 + oid[1]) as u8);
    }
    for &val in &oid[2..] {
        if val < 128 {
            body.push(val as u8);
        } else {
            let mut v = val;
            let mut bytes = vec![(v & 0x7F) as u8];
            v >>= 7;
            while v > 0 {
                bytes.push(((v & 0x7F) | 0x80) as u8);
                v >>= 7;
            }
            bytes.reverse();
            body.extend(bytes);
        }
    }
    tlv(TAG_OID, &body)
}

fn encode_integer(val: i64) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut v = val;
    loop {
        bytes.push((v & 0xFF) as u8);
        v >>= 8;
        let done = (v == 0 && bytes.last().map_or(false, |b| b & 0x80 == 0))
            || (v == -1 && bytes.last().map_or(false, |b| b & 0x80 != 0));
        if done {
            break;
        }
        if bytes.len() > 8 {
            break;
        }
    }
    bytes.reverse();
    tlv(TAG_INTEGER, &bytes)
}

fn build_get(community: &[u8], req_id: i64, version: u8) -> Vec<u8> {
    let varbind = {
        let oid = encode_oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]); // sysDescr.0
        let mut body = oid;
        body.extend(tlv(TAG_NULL, &[]));
        tlv(TAG_SEQUENCE, &body)
    };
    let varbinds = tlv(TAG_SEQUENCE, &varbind);

    let mut pdu_body = encode_integer(req_id);
    pdu_body.extend(encode_integer(0)); // error-status
    pdu_body.extend(encode_integer(0)); // error-index
    pdu_body.extend(varbinds);
    let pdu = tlv(TAG_GET_REQUEST, &pdu_body);

    let mut msg = tlv(TAG_INTEGER, &[version]);
    msg.extend(tlv(TAG_OCTET_STRING, community));
    msg.extend(pdu);
    tlv(TAG_SEQUENCE, &msg)
}

/// True only when `buf` is a GetResponse carrying our request-id.
fn is_valid_response(buf: &[u8], expected_id: i64, expected_version: u8) -> bool {
    let mut pos = 0;
    let Some((tag, msg)) = read_tlv(buf, &mut pos) else {
        return false;
    };
    if tag != TAG_SEQUENCE {
        return false;
    }

    let mut p = 0;
    let Some((t, ver)) = read_tlv(msg, &mut p) else {
        return false;
    };
    if t != TAG_INTEGER || ver.len() != 1 || ver[0] != expected_version {
        return false;
    }
    let Some((t, _community)) = read_tlv(msg, &mut p) else {
        return false;
    };
    if t != TAG_OCTET_STRING {
        return false;
    }
    let Some((t, pdu)) = read_tlv(msg, &mut p) else {
        return false;
    };    if t != TAG_GET_RESPONSE {
        return false;
    }

    let mut q = 0;
    let Some((t, rid)) = read_tlv(pdu, &mut q) else {
        return false;
    };
    if t != TAG_INTEGER || rid.is_empty() {
        return false;
    }
    // Compare the request-id as a signed big-endian integer.
    let mut value: i64 = if rid[0] & 0x80 != 0 { -1 } else { 0 };
    for byte in rid {
        value = (value << 8) | *byte as i64;
    }
    value == expected_id
}

pub async fn auth(
    target: &str,
    port: u16,
    _user: &str,
    pass: &str,
    to: u64,
) -> Result<bool, String> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("bind: {}", e))?;
    let addr = format!("{}:{}", target, port);
    let community = pass.as_bytes();
    let req_id: i64 = rand::thread_rng().gen_range(1..=i32::MAX as i64);
    let budget = Duration::from_secs(to.max(3));

    // SNMPv2c first; fall back to v1 for agents that only speak the old dialect.
    for version in [1u8, 0u8] {
        let packet = build_get(community, req_id, version);
        socket
            .send_to(&packet, &addr)
            .await
            .map_err(|e| format!("send: {}", e))?;

        let mut buf = [0u8; 65535];
        match tokio::time::timeout(budget, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _peer))) => {
                if is_valid_response(&buf[..n], req_id, version) {
                    return Ok(true);
                }
                // A response we cannot parse is not a valid credential.
            }
            Ok(Err(e)) => return Err(format!("recv: {}", e)),
            Err(_) => {
                // Silent drop is what a wrong community looks like.
                continue;
            }
        }
    }

    Ok(false)
}
