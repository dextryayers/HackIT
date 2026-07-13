use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn auth(target: &str, port: u16, _user: &str, pass: &str, to: u64) -> Result<bool, String> {
    let mut s = tokio::time::timeout(
        Duration::from_secs(to),
        TcpStream::connect(format!("{}:{}", target, port)),
    )
    .await
    .map_err(|_| "timeout".to_string())?
    .map_err(|e| format!("conn: {}", e))?;

    let mut version_buf = [0u8; 12];
    tokio::time::timeout(Duration::from_secs(to), s.read_exact(&mut version_buf))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| e.to_string())?;

    let version_str = String::from_utf8_lossy(&version_buf);
    if !version_str.starts_with("RFB") {
        return Err("not VNC".into());
    }

    if version_str.contains("003.008") || version_str.contains("003.007") {
        s.write_all(b"RFB 003.008\n")
            .await
            .map_err(|e| e.to_string())?;
    } else if version_str.contains("003.003") {
        s.write_all(b"RFB 003.003\n")
            .await
            .map_err(|e| e.to_string())?;
    } else {
        return Err(format!("unsupported VNC version: {}", version_str.trim()));
    }

    let auth_result: Result<u8, String> = tokio::time::timeout(Duration::from_secs(to), async {
        let (r, mut w) = s.split();
        let mut br = tokio::io::BufReader::new(r);
        let mut buf = [0u8; 1];
        br.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
        let count = buf[0];
        let mut types = vec![0u8; count as usize];
        br.read_exact(&mut types).await.map_err(|e| e.to_string())?;
        if types.contains(&2) {
            w.write_all(&[2]).await.map_err(|e| e.to_string())?;
            Ok(2u8)
        } else if types.contains(&0) {
            w.write_all(&[0]).await.map_err(|e| e.to_string())?;
            Ok(0u8)
        } else {
            Err("no supported VNC auth type".into())
        }
    })
    .await
    .map_err(|_| "timeout".to_string())?;
    let auth_type: u8 = auth_result?;

    match auth_type {
        0 => Err("VNC: no auth required (type 0)".into()),
        1 => Err("VNC: auth failed (type 1)".into()),
        2 => {
            let mut challenge = [0u8; 16];
            tokio::time::timeout(Duration::from_secs(to), s.read_exact(&mut challenge))
                .await
                .map_err(|_| "timeout".to_string())?
                .map_err(|e| e.to_string())?;

            let key = vnc_des_key(pass);
            let encrypted = vnc_des_encrypt(&key, &challenge);
            s.write_all(&encrypted)
                .await
                .map_err(|e| e.to_string())?;

            let mut result = [0u8; 4];
            s.read_exact(&mut result)
                .await
                .map_err(|e| e.to_string())?;
            if result[3] == 0 {
                Ok(true)
            } else {
                Err("VNC: auth rejected".into())
            }
        }
        _ => Err("VNC: unknown auth scheme".into()),
    }
}

fn vnc_des_key(pass: &str) -> [u8; 8] {
    let mut key = [0u8; 8];
    for (i, b) in pass.bytes().enumerate() {
        if i >= 8 {
            break;
        }
        key[i] = b;
    }
    for i in 0..8 {
        key[i] = (key[i] >> 1) | ((key[i] & 1) << 7);
        key[i] = !key[i];
    }
    key
}

fn vnc_des_encrypt(key: &[u8; 8], data: &[u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    for block in 0..2 {
        let offset = block * 8;
        let k = *key;
        let d: [u8; 8] = data[offset..offset + 8].try_into().unwrap();
        let encrypted = des_encrypt_block(&k, &d);
        result[offset..offset + 8].copy_from_slice(&encrypted);
    }
    result
}

fn des_encrypt_block(key: &[u8; 8], data: &[u8; 8]) -> [u8; 8] {
    let mut state = 0u64;
    for i in 0..8 {
        state = (state << 8) | data[i] as u64;
    }
    let k = des_key_to_u64(key);
    state = des_ff(state, k);
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[7 - i] = (state >> (i * 8)) as u8;
    }
    out
}

fn des_key_to_u64(key: &[u8; 8]) -> u64 {
    let mut k = 0u64;
    for i in 0..8 {
        k = (k << 8) | key[i] as u64;
    }
    k
}

fn des_ff(mut data: u64, key: u64) -> u64 {
    for _round in 0..16 {
        let left = data >> 32;
        let right = data & 0xFFFF_FFFF;
        let f = des_feistel(right, key);
        data = (right << 32) | (left ^ f);
    }
    data
}

fn des_feistel(right: u64, _key: u64) -> u64 {
    let r = right.wrapping_mul(0x23456789);
    let r = r.rotate_left(7);
    let r = r.wrapping_add(0x9ABCDEF);
    r & 0xFFFF_FFFF
}
