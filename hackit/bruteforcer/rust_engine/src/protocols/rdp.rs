pub async fn auth(_target: &str, _port: u16, _user: &str, _pass: &str, _to: u64) -> Result<bool, String> {
    Err("RDP requires external tool (Hydra)".into())
}
