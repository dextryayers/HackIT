use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Clone, Debug)]
pub enum ProxyKind {
    Socks5 { addr: SocketAddr, auth: Option<(String, String)> },
    HttpConnect { addr: SocketAddr, auth: Option<(String, String)> },
    Direct,
}

#[derive(Clone)]
pub struct ProxyChain {
    proxies: Vec<ProxyKind>,
}

impl ProxyChain {
    pub fn new(proxies: Vec<ProxyKind>) -> Self {
        Self { proxies }
    }

    pub fn direct() -> Self {
        Self { proxies: vec![ProxyKind::Direct] }
    }

    pub fn parse_list(input: &str) -> Self {
        let proxies: Vec<ProxyKind> = input
            .split(',')
            .filter_map(|s| {
                let s = s.trim();
                if s.is_empty() {
                    return None;
                }
                if s == "direct" {
                    return Some(ProxyKind::Direct);
                }
                let parts: Vec<&str> = s.split('@').collect();
                let (addr_str, auth) = if parts.len() == 2 {
                    let creds: Vec<&str> = parts[0].split(':').collect();
                    let auth = if creds.len() == 2 {
                        Some((creds[0].to_string(), creds[1].to_string()))
                    } else {
                        None
                    };
                    (parts[1], auth)
                } else {
                    (s, None)
                };
                let kind = if addr_str.starts_with("socks5://") {
                    let a: SocketAddr = addr_str.trim_start_matches("socks5://").parse().ok()?;
                    ProxyKind::Socks5 { addr: a, auth }
                } else if addr_str.starts_with("http://") {
                    let a: SocketAddr = addr_str.trim_start_matches("http://").parse().ok()?;
                    ProxyKind::HttpConnect { addr: a, auth }
                } else {
                    let a: SocketAddr = addr_str.parse().ok()?;
                    ProxyKind::Socks5 { addr: a, auth }
                };
                Some(kind)
            })
            .collect();
        if proxies.is_empty() {
            return Self { proxies: vec![ProxyKind::Direct] };
        }
        Self { proxies }
    }

    pub async fn connect(&self, target: &str, port: u16) -> Result<TcpStream, String> {
        let mut current: Option<TcpStream> = None;
        for proxy in &self.proxies {
            match proxy {
                ProxyKind::Direct => {
                    let stream = TcpStream::connect(format!("{}:{}", target, port))
                        .await
                        .map_err(|e| format!("direct connect: {}", e))?;
                    current = Some(stream);
                }
                ProxyKind::Socks5 { addr, auth } => {
                    let proxy_stream = match current.take() {
                        Some(s) => s,
                        None => TcpStream::connect(addr)
                            .await
                            .map_err(|e| format!("proxy connect: {}", e))?,
                    };
                    current = Some(Self::socks5_handshake(proxy_stream, target, port, auth).await?);
                }
                ProxyKind::HttpConnect { addr, auth } => {
                    let proxy_stream = match current.take() {
                        Some(s) => s,
                        None => TcpStream::connect(addr)
                            .await
                            .map_err(|e| format!("http proxy connect: {}", e))?,
                    };
                    current = Some(Self::http_connect(proxy_stream, target, port, auth).await?);
                }
            }
        }
        current.ok_or_else(|| "no valid proxy".to_string())
    }

    async fn socks5_handshake(
        mut stream: TcpStream,
        target: &str,
        port: u16,
        auth: &Option<(String, String)>,
    ) -> Result<TcpStream, String> {
        let methods = if auth.is_some() { vec![0x00, 0x02] } else { vec![0x00] };
        let mut msg = vec![0x05, methods.len() as u8];
        msg.extend(&methods);
        stream.write_all(&msg).await.map_err(|e| format!("socks5 send: {}", e))?;

        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await.map_err(|e| format!("socks5 recv: {}", e))?;
        if resp[0] != 0x05 {
            return Err("bad SOCKS5 version".into());
        }

        if resp[1] == 0x02 {
            let (u, p) = auth.as_ref().ok_or("auth required but no creds")?;
            let mut auth_msg = vec![0x01, u.len() as u8];
            auth_msg.extend(u.as_bytes());
            auth_msg.push(p.len() as u8);
            auth_msg.extend(p.as_bytes());
            stream.write_all(&auth_msg).await.map_err(|e| format!("socks5 auth send: {}", e))?;
            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await.map_err(|e| format!("socks5 auth recv: {}", e))?;
            if auth_resp[1] != 0x00 {
                return Err("SOCKS5 auth failed".into());
            }
        }

        let mut cmd = vec![0x05, 0x01, 0x00, 0x03, target.len() as u8];
        cmd.extend(target.as_bytes());
        cmd.extend(&port.to_be_bytes());
        stream.write_all(&cmd).await.map_err(|e| format!("socks5 cmd: {}", e))?;
        let mut bound = [0u8; 4];
        stream.read_exact(&mut bound).await.map_err(|e| format!("socks5 resp: {}", e))?;
        if bound[1] != 0x00 {
            return Err(format!("SOCKS5 request rejected: {}", bound[1]));
        }
        let atyp = bound[3];
        let addr_len = match atyp {
            0x01 => 4,
            0x03 => {
                let mut len = [0u8];
                stream.read_exact(&mut len).await.map_err(|e| e.to_string())?;
                len[0] as usize
            }
            0x04 => 16,
            _ => return Err("bad SOCKS5 atyp".into()),
        };
        let mut _addr = vec![0u8; addr_len];
        stream.read_exact(&mut _addr).await.map_err(|e| e.to_string())?;
        let mut _port = [0u8; 2];
        stream.read_exact(&mut _port).await.map_err(|e| e.to_string())?;
        Ok(stream)
    }

    async fn http_connect(
        mut stream: TcpStream,
        target: &str,
        port: u16,
        _auth: &Option<(String, String)>,
    ) -> Result<TcpStream, String> {
        let req = format!("CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n", target, port, target, port);
        stream.write_all(req.as_bytes()).await.map_err(|e| format!("http proxy send: {}", e))?;
        let mut resp = [0u8; 4096];
        let n = stream.read(&mut resp).await.map_err(|e| format!("http proxy recv: {}", e))?;
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        if !resp_str.starts_with("HTTP/1.1 200") && !resp_str.starts_with("HTTP/1.0 200") {
            return Err(format!("HTTP proxy rejected: {}", resp_str.lines().next().unwrap_or("?")));
        }
        Ok(stream)
    }
}

impl Default for ProxyChain {
    fn default() -> Self {
        Self::direct()
    }
}
