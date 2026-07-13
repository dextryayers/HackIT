use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use md5::{Md5, Digest};

pub async fn auth(target: &str, port: u16, user: &str, pass: &str, to: u64) -> Result<bool, String> {
    let mut s = tokio::time::timeout(
        Duration::from_secs(to),
        TcpStream::connect(format!("{}:{}", target, port)),
    )
    .await
    .map_err(|_| "timeout".to_string())?
    .map_err(|e| format!("conn: {}", e))?;

    let _ = netbios_session(&mut s, to).await?;
    let challenge = smb2_negotiate(&mut s, to).await?;
    let authenticated = smb2_session_setup(&mut s, user, pass, &challenge, to).await?;
    Ok(authenticated)
}

async fn netbios_session(s: &mut TcpStream, to: u64) -> Result<(), String> {
    let session_req = [0x81u8, 0x00, 0x00, 0x48];
    let called = [0x20u8; 16];
    let calling = [0x00u8; 16];
    let mut pkt = Vec::with_capacity(72);
    pkt.extend(&session_req);
    pkt.extend(&called);
    pkt.extend(&calling);
    tokio::time::timeout(Duration::from_secs(to), s.write_all(&pkt))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| format!("nbss send: {}", e))?;
    let mut resp = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(to), s.read_exact(&mut resp))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| format!("nbss recv: {}", e))?;
    if resp[0] != 0x82 {
        return Err("NetBIOS session rejected".into());
    }
    Ok(())
}

async fn smb2_negotiate(s: &mut TcpStream, to: u64) -> Result<[u8; 16], String> {
    let req = build_negotiate_req();
    tokio::time::timeout(Duration::from_secs(to), async {
        s.write_all(&req).await.map_err(|e| format!("neg send: {}", e))?;
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).await.map_err(|e| e.to_string())?;
        let _pkt_len = u32::from_le_bytes(hdr) as usize;
        let mut resp = vec![0u8; 256];
        let n = s.read(&mut resp).await.map_err(|e| e.to_string())?;
        if n < 104 {
            return Err("short negotiate response".into());
        }
        let mut challenge = [0u8; 16];
        challenge.copy_from_slice(&resp[88..104]);
        Ok(challenge)
    })
    .await
    .map_err(|_| "timeout".to_string())?
}

fn build_negotiate_req() -> Vec<u8> {
    let dialects = [0x0311u16, 0x0302u16, 0x0300u16, 0x0210u16, 0x0202u16];
    let dc = dialects.len() as u16;
    let body_len = 36 + dc as usize * 2;
    let smb2_off = 4;
    let total = smb2_off + 64 + body_len;
    let mut b = Vec::with_capacity(total);
    b.extend(&(total as u32 - 4).to_le_bytes());
    b.extend(b"\xfeSMB");                // +4 protocol
    b.extend(&[0u8; 2]);                 // +8 struct size
    b.extend(&[0u8; 2]);                 // +10 credit charge
    b.extend(&[0u8; 4]);                 // +12 status
    b.extend(&[0u8; 16]);                // +16 server guid
    b.extend(&[0u8; 4]);                 // +32 flags
    b.extend(&[0u8; 4]);                 // +36 next cmd
    b.extend(&0x0011u32.to_le_bytes());  // +40 command
    b.extend(&0x0001u32.to_le_bytes());  // +44 credits
    b.extend(&[0u8; 8]);                 // +48 msg id
    b.extend(&[0u8; 4]);                 // +56 pid
    b.extend(&[0u8; 4]);                 // +60 tid
    b.extend(&[0u8; 8]);                 // +64 sid
    b.extend(&[0u8; 8]);                 // +72 sig
    b.extend(&36u16.to_le_bytes());      // +80 struct size
    b.extend(&dc.to_le_bytes());         // +82 dialect count
    b.extend(&0x02u16.to_le_bytes());    // +84 security mode
    b.extend(&[0u8; 2]);                 // +86 reserved
    b.extend(&[0u8; 4]);                 // +88 capabilities
    b.extend(&[0u8; 16]);                // +92 client guid
    b.extend(&[0u8; 4]);                 // +108 neg context offset
    b.extend(&[0u8; 2]);                 // +112 neg context count
    b.extend(&[0u8; 2]);                 // +114 reserved
    for d in &dialects { b.extend(&d.to_le_bytes()); }
    b
}

async fn smb2_session_setup(
    s: &mut TcpStream,
    user: &str,
    pass: &str,
    challenge: &[u8; 16],
    to: u64,
) -> Result<bool, String> {
    let lm_hash = ntlm_hash_v1(pass);
    let mut h = Md5::new();
    h.update(&lm_hash);
    h.update(challenge);
    let nt_resp = h.finalize();
    let nt_resp_bytes: [u8; 16] = nt_resp.into();

    let domain = "";
    let workstation = "";
    let mut blob = Vec::new();
    blob.extend(b"NTLMSSP\x00");
    blob.extend(&2u32.to_le_bytes());
    blob.extend(&[0u8; 8]);
    blob.extend(challenge);
    blob.extend(&[0u8; 8]);
    blob.extend(&(user.encode_utf16().count() as u16 * 2).to_le_bytes());
    blob.extend(&(domain.encode_utf16().count() as u16 * 2).to_le_bytes());
    blob.extend(&(workstation.encode_utf16().count() as u16 * 2).to_le_bytes());
    blob.extend(&[0u8; 8]);
    blob.push(0);
    for c in user.encode_utf16() { blob.extend(&c.to_le_bytes()); }
    for c in domain.encode_utf16() { blob.extend(&c.to_le_bytes()); }
    for c in workstation.encode_utf16() { blob.extend(&c.to_le_bytes()); }

    let pkt = build_session_setup_req(&nt_resp_bytes, &blob);
    tokio::time::timeout(Duration::from_secs(to), async {
        s.write_all(&pkt).await.map_err(|e| format!("setup send: {}", e))?;
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).await.map_err(|e| e.to_string())?;
        let _len = u32::from_le_bytes(hdr);
        let mut resp = vec![0u8; 256];
        let n = s.read(&mut resp).await.map_err(|e| e.to_string())?;
        if n < 8 {
            return Err("short session setup response".into());
        }
        let status = u32::from_le_bytes(resp[4..8].try_into().unwrap());
        Ok(status == 0 || status == 0xC0000022)
    })
    .await
    .map_err(|_| "timeout".to_string())?
}

fn ntlm_hash_v1(pass: &str) -> [u8; 16] {
    let mut h = Md5::new();
    for c in pass.encode_utf16() {
        h.update(&c.to_le_bytes());
    }
    let result = h.finalize();
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&result);
    hash
}

fn build_session_setup_req(nt_resp: &[u8; 16], blob: &[u8]) -> Vec<u8> {
    let sec_off = 4 + 64 + 25;
    let total = sec_off + blob.len() + nt_resp.len();
    let mut b = Vec::with_capacity(total);
    b.extend(&(total as u32 - 4).to_le_bytes());
    b.extend(b"\xfeSMB");
    b.extend(&[0u8; 2]);
    b.extend(&[0u8; 2]);
    b.extend(&[0u8; 4]);
    b.extend(&[0u8; 16]);
    b.extend(&[0u8; 4]);
    b.extend(&[0u8; 4]);
    b.extend(&0x0001u32.to_le_bytes());
    b.extend(&0x0001u32.to_le_bytes());
    b.extend(&1u64.to_le_bytes());
    b.extend(&[0u8; 4]);
    b.extend(&[0u8; 4]);
    b.extend(&[0u8; 8]);
    b.extend(&[0u8; 8]);

    b.extend(&25u16.to_le_bytes());
    b.extend(&[0u8; 1]);
    b.extend(&[0u8; 1]);
    b.extend(&[0u8; 4]);
    b.extend(&(sec_off as u16).to_le_bytes());
    b.extend(&(blob.len() as u16).to_le_bytes());
    b.extend(&[0u8; 4]);
    b.extend(&[0u8; 4]);

    b.extend(blob);
    b.extend(nt_resp);
    b
}
