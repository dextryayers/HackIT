//! HTTP authentication — Basic and form POST.
//!
//! The old implementation treated *any* status other than 401/403 as a valid
//! login, so a 404 or a 500 on a server with no auth at all reported every
//! candidate as a hit. That is worse than useless: it fills the result table
//! with lies.
//!
//! Correct behaviour has two modes:
//!   * **Basic** — probe the path unauthenticated first. A 401 proves the path
//!     is protected; a 200 proves it is not and the run is refused as
//!     meaningless. Once protected, success is "the 401 went away".
//!   * **Form** — POST the configured body with `^USER^` / `^PASS^` substituted.
//!     Success is the configured failure string being absent (or the configured
//!     success string being present). Without a failure marker the run is
//!     refused, because "the page loaded" is not a login.

use crate::protocols::ProtoOpts;
use std::sync::OnceLock;
use std::time::Duration;

fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(5))
            .timeout(Duration::from_secs(15))
            .pool_max_idle_per_host(4)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

fn scheme(port: u16, opts: &ProtoOpts) -> &'static str {
    if opts.http_tls || port == 443 || port == 8443 {
        "https"
    } else {
        "http"
    }
}

fn base_url(target: &str, port: u16, opts: &ProtoOpts) -> String {
    let host = if target.contains(':') && !target.starts_with('[') {
        format!("[{}]", target)
    } else {
        target.to_string()
    };
    format!("{}://{}:{}", scheme(port, opts), host, port)
}

fn path(opts: &ProtoOpts) -> &str {
    if opts.http_path.is_empty() {
        "/"
    } else {
        opts.http_path.as_str()
    }
}

fn render(template: &str, user: &str, pass: &str) -> String {
    template
        .replace("^USER^", user)
        .replace("^PASS^", pass)
        .replace("^PASSWORD^", pass)
}

pub async fn auth(
    target: &str,
    port: u16,
    user: &str,
    pass: &str,
    to: u64,
    opts: &ProtoOpts,
) -> Result<bool, String> {
    let client = client();
    let url = format!("{}{}", base_url(target, port, opts), path(opts));
    let timeout = Duration::from_secs(to.max(3));

    if !opts.http_body.is_empty() {
        return form_auth(client, &url, user, pass, timeout, opts).await;
    }

    // ── Basic ──
    // One unauthenticated probe per candidate is wasteful; the caller may set
    // `http_baseline` to a cached status. Absent that, probe every time.
    let probe = client
        .get(&url)
        .timeout(timeout)
        .send()
        .await
        .map_err(|e| format!("probe: {}", e))?;
    let baseline = probe.status().as_u16();

    if baseline != 401 && baseline != 407 && !opts.http_force_basic {
        return Err(format!(
            "no Basic challenge on {} (status {}); set --http-force-basic or --http-body for a form",
            path(opts),
            baseline
        ));
    }

    let mut request = client.get(&url).basic_auth(user, Some(pass)).timeout(timeout);
    for header in &opts.http_header {
        if let Some((name, value)) = header.split_once(':') {
            request = request.header(name.trim(), value.trim());
        }
    }
    let response = request
        .send()
        .await
        .map_err(|e| format!("request: {}", e))?;

    Ok(response.status().as_u16() != 401 && response.status().as_u16() != 407)
}

async fn form_auth(
    client: &reqwest::Client,
    url: &str,
    user: &str,
    pass: &str,
    timeout: Duration,
    opts: &ProtoOpts,
) -> Result<bool, String> {
    let body = render(&opts.http_body, user, pass);
    let mut request = if opts.http_method.eq_ignore_ascii_case("POST") {
        client.post(url)
    } else {
        client.get(url)
    }
    .timeout(timeout);

    if opts.http_method.eq_ignore_ascii_case("POST") {
        request = request
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body);
    } else if !body.is_empty() {
        request = request.query(&body);
    }
    for header in &opts.http_header {
        if let Some((name, value)) = header.split_once(':') {
            request = request.header(name.trim(), value.trim());
        }
    }

    let response = request
        .send()
        .await
        .map_err(|e| format!("request: {}", e))?;
    let status = response.status().as_u16();
    let text = response.text().await.unwrap_or_default();

    if !opts.http_success.is_empty() {
        return Ok(text.contains(&opts.http_success));
    }
    if opts.http_fail.is_empty() {
        return Err(
            "form mode needs a failure marker (--http-fail) or a success marker (--http-success)"
                .into(),
        );
    }
    // A 5xx is the server breaking, not a credential verdict.
    if status >= 500 {
        return Err(format!("server error {}", status));
    }
    Ok(!text.contains(&opts.http_fail))
}
