use std::time::Duration;
use tokio::net::UdpSocket;
use rand::Rng;

pub async fn auth(target: &str, port: u16, _user: &str, pass: &str, to: u64) -> Result<bool, String> {
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("bind: {}", e))?;
    let target_addr = format!("{}:{}", target, port);

    let community = pass.as_bytes();
    let req_id: u32 = rand::thread_rng().gen();
    let pkt = build_snmp_v2c_get(community, req_id);

    sock.send_to(&pkt, &target_addr)
        .await
        .map_err(|e| format!("send: {}", e))?;

    let mut buf = [0u8; 65535];
    let n = tokio::time::timeout(Duration::from_secs(to), sock.recv_from(&mut buf))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| format!("recv: {}", e))?
        .0;

    if n < 20 {
        return Err("short SNMP response".into());
    }

    if buf[0] == 0x30 && buf[n - 1] == 0x00 {
        Err("SNMP: auth failed (no response)".into())
    } else {
        Ok(true)
    }
}

fn build_snmp_v2c_get(community: &[u8], req_id: u32) -> Vec<u8> {
    let version = [0x02, 0x01, 0x01]; // SNMPv2c
    let community_tlv = encode_octet_string(community);
    let pdu_type = 0xA0u8; // GetRequest
    let oid = encode_oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]); // sysDescr.0
    let varbind = build_varbind(&oid);
    let varbind_list = build_tlv(0x30, &varbind);
    let _empty_val = [0x05, 0x00]; // null value

    let rid = encode_integer(req_id as i64);
    let err = [0x02, 0x01, 0x00];
    let err_idx = [0x02, 0x01, 0x00];

    let mut pdu_body = Vec::new();
    pdu_body.extend(&rid);
    pdu_body.extend(&err);
    pdu_body.extend(&err_idx);
    pdu_body.extend(&varbind_list);

    let pdu = build_tlv(pdu_type, &pdu_body);

    let mut inner = Vec::new();
    inner.extend(&version);
    inner.extend(&community_tlv);
    inner.extend(&pdu);

    let outer = build_tlv(0x30, &inner);
    outer
}

fn build_varbind(oid: &[u8]) -> Vec<u8> {
    let null_val = [0x05, 0x00];
    let mut body = Vec::new();
    body.extend(oid);
    body.extend(&null_val);
    build_tlv(0x30, &body)
}

fn encode_oid(oid: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    if oid.len() >= 2 {
        out.push((oid[0] * 40 + oid[1]) as u8);
    }
    for &val in &oid[2..] {
        if val < 128 {
            out.push(val as u8);
        } else {
            let mut v = val;
            let mut bytes = Vec::new();
            bytes.push((v & 0x7F) as u8);
            v >>= 7;
            while v > 0 {
                bytes.push(((v & 0x7F) | 0x80) as u8);
                v >>= 7;
            }
            bytes.reverse();
            out.extend(&bytes);
        }
    }
    encode_tlv(0x06, &out)
}

fn encode_integer(val: i64) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut v = val;
    let neg = v < 0;
    bytes.push((v & 0xFF) as u8);
    v >>= 8;
    while v != 0 && v != -1 {
        bytes.push((v & 0xFF) as u8);
        v >>= 8;
    }
    if neg && (bytes.last().unwrap() & 0x80) == 0 {
        bytes.push(0xFF);
    }
    if !neg && (bytes.last().unwrap() & 0x80) != 0 {
        bytes.push(0x00);
    }
    bytes.reverse();
    encode_tlv(0x02, &bytes)
}

fn encode_octet_string(data: &[u8]) -> Vec<u8> {
    encode_tlv(0x04, data)
}

fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 128 {
        out.push(value.len() as u8);
    } else {
        let mut len_bytes = Vec::new();
        let mut l = value.len();
        while l > 0 {
            len_bytes.push((l & 0xFF) as u8);
            l >>= 8;
        }
        len_bytes.reverse();
        out.push(0x80 | len_bytes.len() as u8);
        out.extend(&len_bytes);
    }
    out.extend(value);
    out
}

fn build_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    encode_tlv(tag, value)
}
