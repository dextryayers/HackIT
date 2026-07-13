use std::time::Duration;

pub async fn auth(target: &str, port: u16, user: &str, pass: &str, to: u64) -> Result<bool, String> {
    use ldap3::LdapConn;
    let addr = format!("ldap://{}:{}", target, port);
    match LdapConn::new(&addr) {
        Ok(mut conn) => {
            conn.with_timeout(Duration::from_secs(to));
            match conn.simple_bind(user, pass) {
                Ok(res) => {
                    let _ = conn.unbind();
                    Ok(res.rc == 0)
                }
                Err(e) => Err(e.to_string()),
            }
        }
        Err(e) => Err(e.to_string()),
    }
}
