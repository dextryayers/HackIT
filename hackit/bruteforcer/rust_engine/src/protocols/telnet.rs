//! Telnet authentication.
//!
//! Telnet has no authentication protocol — it is a byte stream that asks
//! questions in whatever words its author chose. The only reliable signal is
//! therefore *conversational*: wait for a login prompt, answer it, wait for a
//! password prompt, answer that, then decide from what comes back.
//!
//! Two things make naive implementations wrong:
//!   * IAC option negotiation (0xFF sequences) must be stripped and answered,
//!     or the session desynchronises on the first byte of the banner.
//!   * "response contains `$`" is not a login test. Banners contain `$`.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;

const LOGIN_PROMPTS: &[&str] = &[
    "login:", "login :", "username:", "user name:", "user:", "login as:",
    "name:", "account:", "login prompt",
];
const PASSWORD_PROMPTS: &[&str] = &[
    "password:", "passwd:", "password :", "pass:", "pin:",
];
const FAILURE_MARKERS: &[&str] = &[
    "login incorrect", "incorrect password", "invalid password", "bad password",
    "authentication failed", "authentication failure", "login failed",
    "access denied", "permission denied", "not authorized", "unauthorized",
    "sorry", "try again", "invalid login", "invalid user", "unknown user",
    "no such user", "login invalid", "wrong password", "denied",
];
const SUCCESS_MARKERS: &[&str] = &[
    "last login", "welcome to", "successfully logged", "login successful",
    "have a lot of fun", "busybox", "shell", "connected to",
];

/// Accumulates the readable half of a telnet stream, answering IAC as it goes.
struct TelnetReader {
    buf: Vec<u8>,
    text: String,
}

impl TelnetReader {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            text: String::new(),
        }
    }

    /// Pull one chunk from the socket, strip negotiations, append the text.
    async fn pump(
        &mut self,
        stream: &mut TcpStream,
        out: &mut Vec<u8>,
        window: Duration,
    ) -> Result<usize, String> {
        let mut chunk = [0u8; 4096];
        let n = tokio::time::timeout(window, stream.read(&mut chunk))
            .await
            .map_err(|_| "read timeout".to_string())?
            .map_err(|e| format!("read: {}", e))?;
        if n == 0 {
            return Ok(0);
        }
        self.buf.extend_from_slice(&chunk[..n]);

        let mut i = 0;
        while i < self.buf.len() {
            if self.buf[i] != IAC {
                let start = i;
                while i < self.buf.len() && self.buf[i] != IAC {
                    i += 1;
                }
                self.text.push_str(&String::from_utf8_lossy(&self.buf[start..i]));
                continue;
            }
            // IAC — need at least the command byte.
            if i + 1 >= self.buf.len() {
                break;
            }
            let cmd = self.buf[i + 1];
            match cmd {
                WILL | WONT | DO | DONT => {
                    if i + 2 >= self.buf.len() {
                        break;
                    }
                    let opt = self.buf[i + 2];
                    // Refuse every option: we only need the login dialogue and
                    // agreeing to anything invites a terminal-type subnegotiation.
                    let reply = match cmd {
                        WILL => vec![IAC, DONT, opt],
                        DO => vec![IAC, WONT, opt],
                        _ => Vec::new(),
                    };
                    out.extend_from_slice(&reply);
                    i += 3;
                }
                SB => {
                    // Skip to IAC SE. If it has not arrived yet, stop and wait
                    // for the next chunk — the buffer is drained up to `i`.
                    let mut j = i + 2;
                    let mut closed = false;
                    while j + 1 < self.buf.len() {
                        if self.buf[j] == IAC && self.buf[j + 1] == SE {
                            j += 2;
                            closed = true;
                            break;
                        }
                        j += 1;
                    }
                    if !closed {
                        break;
                    }
                    i = j;
                }
                IAC => {
                    // Escaped 0xFF literal.
                    self.text.push('\u{fffd}');
                    i += 2;
                }
                _ => i += 2,
            }
        }
        self.buf.drain(..i.min(self.buf.len()));
        Ok(n)
    }

    fn tail(&self, n: usize) -> String {
        let chars: Vec<char> = self.text.chars().collect();
        let start = chars.len().saturating_sub(n);
        chars[start..].iter().collect()
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    let low = haystack.to_ascii_lowercase();
    needles.iter().any(|n| low.contains(n))
}

/// Wait until one of `needles` shows up in the accumulated text, the socket
/// closes, or the deadline passes. Returns whether a needle matched.
async fn expect(
    reader: &mut TelnetReader,
    stream: &mut TcpStream,
    needles: &[&str],
    deadline: Duration,
    settle: Duration,
) -> Result<bool, String> {
    let start = std::time::Instant::now();
    loop {
        if contains_any(&reader.text, needles) {
            return Ok(true);
        }
        if start.elapsed() >= deadline {
            return Ok(false);
        }
        let mut out = Vec::new();
        let window = settle.min(deadline.saturating_sub(start.elapsed()));
        let n = reader.pump(stream, &mut out, window).await?;
        if !out.is_empty() {
            stream
                .write_all(&out)
                .await
                .map_err(|e| format!("iac reply: {}", e))?;
        }
        if n == 0 {
            return Ok(contains_any(&reader.text, needles));
        }
    }
}

pub async fn auth(
    target: &str,
    port: u16,
    user: &str,
    pass: &str,
    to: u64,
) -> Result<bool, String> {
    let connect = tokio::time::timeout(
        Duration::from_secs(to),
        TcpStream::connect(format!("{}:{}", target, port)),
    )
    .await
    .map_err(|_| "connect timeout".to_string())?
    .map_err(|e| format!("connect: {}", e))?;

    let mut stream = connect;
    let _ = stream.set_nodelay(true);
    let mut reader = TelnetReader::new();
    let total = Duration::from_secs(to.max(5));
    let settle = Duration::from_millis(400);

    // Banner + login prompt.
    let saw_login = expect(&mut reader, &mut stream, LOGIN_PROMPTS, total, settle).await?;
    if !saw_login {
        // Some appliances ask for the password first (rare) or skip straight to
        // a password prompt. If neither appeared there is nothing to brute.
        if !contains_any(&reader.text, PASSWORD_PROMPTS) {
            return Err(format!(
                "no login prompt (banner: {:?})",
                reader.tail(120)
            ));
        }
    } else {
        stream
            .write_all(format!("{}\r\n", user).as_bytes())
            .await
            .map_err(|e| format!("write user: {}", e))?;
    }

    // Password prompt.
    if !expect(&mut reader, &mut stream, PASSWORD_PROMPTS, total, settle).await? {
        if contains_any(&reader.text, FAILURE_MARKERS) {
            return Ok(false);
        }
        return Err(format!("no password prompt (saw {:?})", reader.tail(120)));
    }

    reader.text.clear();
    stream
        .write_all(format!("{}\r\n", pass).as_bytes())
        .await
        .map_err(|e| format!("write pass: {}", e))?;

    // Decide from what the server says next. Wait for a failure marker or a
    // shell prompt, whichever lands first, within the remaining budget.
    let deadline = Duration::from_secs(to.max(6));
    let start = std::time::Instant::now();
    loop {
        let tail = reader.tail(512);
        if contains_any(&tail, FAILURE_MARKERS) {
            return Ok(false);
        }
        // A login prompt coming back means the password was refused.
        if contains_any(&tail, LOGIN_PROMPTS) && !contains_any(&tail, SUCCESS_MARKERS) {
            return Ok(false);
        }
        let trimmed = tail.trim_end();
        if let Some(last) = trimmed.chars().last() {
            if matches!(last, '$' | '#' | '%' | '>') && trimmed.len() > 1 {
                return Ok(true);
            }
        }
        if contains_any(&tail, SUCCESS_MARKERS) {
            return Ok(true);
        }
        if start.elapsed() >= deadline {
            // Nothing conclusive. An open session that stopped asking questions
            // is a shell we were not told about; a closed one is a refusal.
            return Ok(!reader.text.is_empty() && !contains_any(&reader.text, LOGIN_PROMPTS));
        }
        let mut out = Vec::new();
        let n = reader.pump(&mut stream, &mut out, settle).await?;
        if !out.is_empty() {
            stream
                .write_all(&out)
                .await
                .map_err(|e| format!("iac reply: {}", e))?;
        }
        if n == 0 {
            return Ok(false);
        }
    }
}
