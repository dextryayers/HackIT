//! LDAP simple bind.
//!
//! `ldap3`'s synchronous API is the correct one for a one-shot bind, but calling
//! it from an async task blocks the reactor thread for the whole TCP round trip.
//! Every attempt therefore runs on the blocking pool; the async wrapper only
//! owns the timeout.

use std::time::Duration;

pub async fn auth(
    target: &str,
    port: u16,
    user: &str,
    pass: &str,
    to: u64,
) -> Result<bool, String> {
    let host = target.to_string();
    let bind_dn = user.to_string();
    let bind_pw = pass.to_string();

    let task = tokio::task::spawn_blocking(move || {
        use ldap3::LdapConn;
        let scheme = if port == 636 { "ldaps" } else { "ldap" };
        let url = format!("{}://{}:{}", scheme, host, port);
        let mut conn = LdapConn::new(&url).map_err(|e| format!("connect: {}", e))?;
        conn.with_timeout(Duration::from_secs(to));
        let result = conn.simple_bind(&bind_dn, &bind_pw);
        let _ = conn.unbind();
        match result {
            Ok(res) => {
                // rc 0 = success. 49 = invalid credentials. Anything else is a
                // server-side refusal, which is still a denial, not a transport
                // error — but 49 is the one that means "wrong password".
                Ok(res.rc == 0)
            }
            Err(e) => {
                let text = e.to_string();
                // ldap3 surfaces a rejected bind as an error carrying the rc.
                if text.contains("rc=49") || text.contains("Invalid credentials") {
                    Ok(false)
                } else {
                    Err(text)
                }
            }
        }
    });

    match tokio::time::timeout(Duration::from_secs(to + 2), task).await {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => Err(format!("ldap task: {}", e)),
        Err(_) => Err("timeout".into()),
    }
}
