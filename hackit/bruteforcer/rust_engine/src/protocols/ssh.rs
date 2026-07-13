use std::net::TcpStream;
use std::time::Duration;

pub async fn auth(target: &str, port: u16, user: &str, pass: &str, to: u64) -> Result<bool, String> {
    use ssh2::Session;
    let addr = format!("{}:{}", target, port);
    let u = user.to_string();
    let p = pass.to_string();
    tokio::time::timeout(Duration::from_secs(to), async {
        tokio::task::spawn_blocking(move || {
            let tcp = TcpStream::connect(&addr).map_err(|e| format!("tcp:{}", e))?;
            tcp.set_read_timeout(Some(Duration::from_secs(to))).ok();
            tcp.set_write_timeout(Some(Duration::from_secs(to))).ok();
            let mut s = Session::new().map_err(|e| format!("sess:{}", e))?;
            s.set_tcp_stream(tcp);
            s.handshake().map_err(|e| format!("hs:{}", e))?;
            s.userauth_password(&u, &p).map_err(|e| format!("auth:{}", e))?;
            Ok(s.authenticated())
        })
        .await
        .map_err(|e| e.to_string())?
    })
    .await
    .map_err(|_| "timeout".to_string())?
    .map_err(|e| e)
}
