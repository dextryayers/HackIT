--[[
    probe_runner.lua — protocol-accurate banner engine for the Lua path.

    Mirrors the Go/Rust/Python probe engines: an ordered probe plan per port, an
    accumulating reader that drains until the peer goes quiet, and per-protocol
    decoders. Previously this module fired one payload and read one buffer, so
    multi-line greetings were truncated and every service looked like "unknown".
]]

local socket = require("socket")

local ProbeRunner = {}
ProbeRunner.__index = ProbeRunner

local BANNER_MAX = 16384
local GREET_WAIT = 0.45
local PROBE_WAIT = 0.90
local IDLE_GAP = 0.12
local MAX_STAGES = 6

local GREETING_PORTS = {
    [21] = true, [22] = true, [23] = true, [25] = true, [110] = true,
    [111] = true, [119] = true, [143] = true, [445] = true, [465] = true,
    [587] = true, [873] = true, [990] = true, [993] = true, [995] = true,
    [1521] = true, [3306] = true, [3389] = true, [5432] = true,
    [5671] = true, [5672] = true, [5900] = true, [6379] = true,
    [6667] = true, [9042] = true, [9160] = true, [11211] = true,
    [16379] = true, [27017] = true,
}

local NOT_HTTP = {
    [21] = true, [22] = true, [23] = true, [25] = true, [110] = true,
    [143] = true, [465] = true, [587] = true, [636] = true, [990] = true,
    [993] = true, [995] = true, [1883] = true, [2222] = true, [3306] = true,
    [3389] = true, [5222] = true, [5432] = true, [5671] = true,
    [5672] = true, [5900] = true, [6379] = true, [8883] = true,
    [9042] = true, [11211] = true, [25565] = true, [27017] = true,
}

local NOT_TLS = {
    [21] = true, [22] = true, [23] = true, [25] = true, [110] = true,
    [143] = true, [1883] = true, [3306] = true, [5222] = true,
    [5672] = true, [6379] = true, [6667] = true, [11211] = true,
    [25565] = true, [27017] = true,
}

local HTTP_PORTS = {
    [80] = true, [81] = true, [82] = true, [83] = true, [84] = true, [85] = true,
    [88] = true, [90] = true, [443] = true, [3000] = true, [4000] = true,
    [5000] = true, [631] = true, [7000] = true, [7001] = true, [7080] = true,
    [7443] = true, [8000] = true, [8001] = true, [8008] = true, [8009] = true,
    [8010] = true, [8069] = true, [8080] = true, [8081] = true, [8082] = true,
    [8088] = true, [8090] = true, [8123] = true, [8200] = true, [8300] = true,
    [8443] = true, [8444] = true, [8500] = true, [8888] = true, [9000] = true,
    [9090] = true, [9091] = true, [9200] = true, [9443] = true, [10000] = true,
    [15672] = true, [18080] = true, [18090] = true, [2375] = true,
    [2379] = true, [5984] = true, [6443] = true, [10250] = true,
}

local USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) PortStorm-Lua/3.1"

-- ── helpers ──────────────────────────────────────────────────────

local function http_payload(host, port, path)
    path = path or "/"
    return string.format(
        "GET %s HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: %s\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        path, host, port, USER_AGENT
    )
end

local function postgres_startup()
    local params = "user\0hackit\0database\0postgres\0\0"
    local len = 8 + #params
    return string.char(
        math.floor(len / 16777216) % 256, math.floor(len / 65536) % 256,
        math.floor(len / 256) % 256, len % 256,
        0, 3, 0, 0
    ) .. params
end

local function mongo_ismaster()
    local doc = "\19\0\0\0\16ismaster\0\1\0\0\0\0"
    local msg = "\0\0\0\0\1\0\0\0\0\0\0\0\212\7\0\0\0\0\0\0"
        .. "admin.$cmd\0\0\0\0\0" .. "\0\0\0\0\255\255\255\255" .. doc
    local len = #msg
    return string.char(len % 256, math.floor(len / 256) % 256,
        math.floor(len / 65536) % 256, math.floor(len / 16777216) % 256)
        .. msg:sub(5)
end

local function cassandra_startup(version)
    local body = "\0\1\0\11CQL_VERSION\0\5" .. "3.0.0"
    return string.char(version or 4, 0, 0, 0, 1, 0, 0, 0, #body) .. body
end

local function rdp_negotiate()
    return string.char(3, 0, 0, 19, 14, 224, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0)
end

local function smb_negotiate()
    local body = "\0\0\0\0\254SMB" .. "\64\0" .. "\4\0" .. "\1\0"
        .. "\0\0\0\0" .. "\0\0\0\0" .. string.rep("\0", 16) .. string.rep("\0", 4)
        .. string.char(2, 2, 16, 2, 0, 3, 2, 3, 17, 3)
    local len = #body - 4
    return string.char(0, 0, 0, len) .. body:sub(5)
end

local function kafka_versions()
    local body = "\0\18\0\0\0\0\0\1\0\6hackit"
    local len = #body
    return string.char(0, 0, 0, len) .. body
end

local function sanitize(raw)
    return (raw:gsub("[^\9\10\13\32-\126]", ""))
end

local function first_line(text)
    return (text:match("^[^\r\n]*") or ""):gsub("^%s+", ""):gsub("%s+$", "")
end

local function truncate(text, n)
    text = text:gsub("%s+", " ")
    if #text <= n then return text end
    return text:sub(1, n) .. "..."
end

-- ── construction ─────────────────────────────────────────────────

function ProbeRunner.new()
    local self = setmetatable({}, ProbeRunner)
    self.results = {}
    self.timeout = 5
    return self
end

function ProbeRunner:set_timeout(seconds)
    self.timeout = seconds or 5
end

function ProbeRunner:tcp_connect(host, port, timeout)
    local client = socket.tcp()
    client:settimeout(timeout or self.timeout)
    local ok, err = client:connect(host, tonumber(port))
    if not ok then
        client:close()
        return nil, err
    end
    return client, nil
end

-- Drain until the peer pauses, closes, or the cap is reached.
local function read_until_quiet(client, first, limit)
    limit = limit or BANNER_MAX
    local out = {}
    local total = 0

    client:settimeout(first or PROBE_WAIT)
    while total < limit do
        local data, err, partial = client:receive(4096)
        if data and #data > 0 then
            table.insert(out, data)
            total = total + #data
            client:settimeout(IDLE_GAP)
        elseif partial and #partial > 0 then
            table.insert(out, partial)
            total = total + #partial
            break
        else
            break
        end
    end
    return table.concat(out)
end

function ProbeRunner:send_payload(host, port, payload, timeout)
    local client, err = self:tcp_connect(host, port, timeout)
    if not client then
        return nil, err
    end
    if payload and #payload > 0 then
        local ok, serr = client:send(payload)
        if not ok then
            client:close()
            return nil, serr
        end
    end
    local data = read_until_quiet(client, timeout or PROBE_WAIT)
    client:close()
    if #data == 0 then
        return nil, "empty"
    end
    return data, nil
end

-- ── plan ─────────────────────────────────────────────────────────

function ProbeRunner:build_plan(host, port)
    local plan = {}
    local function add(name, payload, settle)
        plan[#plan + 1] = { name = name, payload = payload, settle = settle or PROBE_WAIT }
    end

    if GREETING_PORTS[port] then
        add("greeting", nil, GREET_WAIT)
    end

    if port == 25 or port == 465 or port == 587 or port == 2525 then
        add("smtp", "EHLO hackit.local\r\n")
    elseif port == 110 then
        add("pop3", "CAPA\r\n")
    elseif port == 143 then
        add("imap", "a1 CAPABILITY\r\n")
    elseif port == 119 then
        add("nntp", "MODE READER\r\n")
    elseif port == 21 then
        add("ftp", "FEAT\r\n")
        add("ftp-tls", "AUTH TLS\r\n")
    elseif port >= 5432 and port <= 5440 then
        add("postgres-ssl", string.char(0, 0, 0, 8, 4, 210, 22, 47))
        add("postgres-startup", postgres_startup())
    elseif port >= 6379 and port <= 6385 then
        add("redis", "INFO server\r\n")
    elseif port == 16379 then
        add("redis-cluster", "CLUSTER INFO\r\n")
    elseif port >= 27017 and port <= 27025 then
        add("mongodb", mongo_ismaster())
    elseif port == 1433 then
        add("mssql", string.char(0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00, 0x20, 0x00, 0x01, 0x02,
            0x00, 0x21, 0x00, 0x01, 0x03, 0x00, 0x22, 0x00, 0x04, 0x04, 0x00,
            0x26, 0x00, 0x01, 0xff, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
    elseif port >= 1521 and port <= 1527 then
        add("oracle-tns", string.char(0, 0x57, 0, 0, 1, 0, 0, 0, 1, 0x3a, 1, 0x2c, 0, 0, 8, 0,
            0x7f, 0xff, 0x7f, 8, 0, 0, 0, 1, 0, 0x3d, 0, 0, 0, 0, 0, 0))
    elseif port == 9042 or port == 9043 or port == 9044 then
        add("cassandra", cassandra_startup(4))
    elseif port == 9160 then
        add("cassandra-thrift", string.char(0x80, 1, 0, 1, 0, 0, 0, 1))
    elseif port >= 5900 and port <= 5910 then
        add("vnc", "RFB 003.008\n")
    elseif port >= 3389 and port <= 3392 then
        add("rdp", rdp_negotiate())
    elseif port == 389 or port == 3268 then
        add("ldap", string.char(0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00))
    elseif port == 5672 or port == 5671 then
        add("amqp", "AMQP\0\0\9\1")
    elseif port == 1883 or port == 8883 then
        add("mqtt", string.char(0x10, 0x0e, 0, 4, 77, 81, 84, 84, 4, 0, 0, 0, 0, 0, 0, 0))
    elseif port >= 9092 and port <= 9097 then
        add("kafka", kafka_versions())
    elseif port == 4222 or port == 6222 then
        add("nats", "CONNECT {\"verbose\":false}\r\nPING\r\n")
    elseif port >= 11211 and port <= 11215 then
        add("memcached", "stats\r\n")
    elseif port == 2181 then
        add("zookeeper", "srvr")
        add("zookeeper-ruok", "ruok")
    elseif port == 2375 or port == 2376 or port == 4243 then
        add("docker", http_payload(host, port, "/version"))
    elseif port == 6443 or port == 6444 or port == 8001 then
        add("kubernetes", http_payload(host, port, "/version"))
    elseif port >= 9200 and port <= 9210 then
        add("elasticsearch", http_payload(host, port))
    elseif port == 445 then
        add("smb", smb_negotiate())
    elseif port == 873 then
        add("rsync", "@RSYNCD: 31.0\n")
    elseif port == 554 or port == 8554 then
        add("rtsp", "OPTIONS rtsp://localhost RTSP/1.0\r\nCSeq: 1\r\n\r\n")
    elseif port == 5060 then
        add("sip", "OPTIONS sip:probe@localhost SIP/2.0\r\nVia: SIP/2.0/TCP localhost\r\nFrom: <sip:probe@localhost>;tag=1\r\nTo: <sip:probe@localhost>\r\nCall-ID: 1@localhost\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n")
    end

    if HTTP_PORTS[port] or not NOT_HTTP[port] then
        add("http", http_payload(host, port))
    end
    if not NOT_TLS[port] then
        add("tls", nil)
    end
    add("crlf", "\r\n", 0.4)

    local trimmed = {}
    for i = 1, math.min(#plan, MAX_STAGES) do
        trimmed[i] = plan[i]
    end
    return trimmed
end

-- ── decoders ─────────────────────────────────────────────────────

local function is_tls(raw)
    if #raw < 5 then return false end
    local b1, b2, b3 = raw:byte(1, 3)
    return b1 == 0x16 and b2 == 0x03 and b3 <= 0x04
end

local function decode_mysql(raw)
    if #raw < 6 then return nil end
    local b4, b5 = raw:byte(4, 5)
    if b4 ~= 0 or b5 ~= 10 then return nil end
    local rest = raw:sub(6)
    local endpos = rest:find("\0", 1, true)
    if not endpos or endpos <= 1 or endpos > 64 then return nil end
    local version = rest:sub(1, endpos - 1)
    if version:match("%d") then return version end
    return nil
end

local function decode_http(text, tls)
    local parts = {}
    local product, version = "HTTP", ""
    for line in text:gmatch("[^\r\n]+") do
        local trimmed = line:gsub("^%s+", ""):gsub("%s+$", "")
        if trimmed:match("^HTTP/%d%.%d%s+%d%d%d") then
            parts[#parts + 1] = trimmed
        else
            local server = trimmed:match("^[Ss]erver:%s*(.+)$")
            if server then
                parts[#parts + 1] = "Server: " .. server
                local first, ver = server:match("^([^/%s]+)/([^%s]+)")
                if first then
                    product = first
                    version = ver:gsub(";$", "")
                else
                    local p2, v2 = server:match("^(%S+)%s+(%S+)")
                    product = p2 or server
                    if v2 and v2:match("%d+%.%d+") then version = v2:gsub(";$", "") end
                end
            else
                local low = trimmed:lower()
                if low:match("^x%-powered%-by:") or low:match("^via:") or low:match("^content%-type:") then
                    parts[#parts + 1] = trimmed
                end
            end
        end
        if #parts >= 5 then break end
    end
    local title = text:match("<[Tt][Ii][Tt][Ll][Ee][^>]*>(.-)</[Tt][Ii][Tt][Ll][Ee]>")
    if title and #title < 120 then
        parts[#parts + 1] = "Title: " .. title:gsub("%s+", " ")
    end
    return {
        protocol = tls and "https" or "http",
        product = product,
        version = version,
        banner = table.concat(parts, " | "),
        confidence = tls and 0.99 or (product ~= "HTTP" and 0.97 or 0.90),
    }
end

local TEXT_RULES = {
    { proto = "ftp", product = "FTP", needles = { " 220 ", "vsftpd", "proftpd", "pure-ftpd", "filezilla" }, conf = 0.92 },
    { proto = "smtp", product = "SMTP", needles = { "esmtp", "postfix", "exim", "sendmail", "smtp" }, conf = 0.90 },
    { proto = "pop3", product = "POP3", needles = { "+ok", "pop3", "dovecot" }, conf = 0.88 },
    { proto = "imap", product = "IMAP", needles = { "* ok", "imap", "dovecot", "cyrus" }, conf = 0.88 },
    { proto = "telnet", product = "Telnet", needles = { "login:", "password:" }, conf = 0.70 },
    { proto = "memcached", product = "Memcached", needles = { "curr_items", "version " }, conf = 0.85 },
    { proto = "rsync", product = "rsync", needles = { "@rsyncd" }, conf = 0.97 },
    { proto = "zookeeper", product = "ZooKeeper", needles = { "imok", "mode:" }, conf = 0.85 },
    { proto = "elasticsearch", product = "Elasticsearch", needles = { "you know, for search", "lucene_version" }, conf = 0.95 },
    { proto = "prometheus", product = "Prometheus", needles = { "# help", "# type" }, conf = 0.85 },
    { proto = "sip", product = "SIP", needles = { "sip/2.0" }, conf = 0.92 },
    { proto = "rtsp", product = "RTSP", needles = { "rtsp/1.0" }, conf = 0.95 },
    { proto = "xmpp", product = "XMPP", needles = { "stream:stream", "jabber" }, conf = 0.90 },
    { proto = "irc", product = "IRC", needles = { "ircd", "notice auth" }, conf = 0.85 },
}

local EXPECTED_PORT = {
    ftp = { 21, 2100, 2121, 8021 },
    ssh = { 22, 222, 2022, 2222, 2223, 2224, 2225, 2226, 2227, 2228, 2229, 2230 },
    smtp = { 25, 465, 587, 2525 },
    pop3 = { 110, 995 },
    imap = { 143, 993 },
    mysql = { 3306, 3307, 3308, 3309, 3310, 3311, 3312, 33060 },
    redis = { 6379, 6380, 6381, 6382, 6383, 6384, 6385, 16379, 26379 },
    mongodb = { 27017, 27018, 27019, 27020, 27021, 27022, 27023, 27024, 27025 },
    memcached = { 11211, 11212, 11213, 11214, 11215 },
    vnc = { 5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909, 5910 },
    rsync = { 873 },
}

local function port_is_expected(proto, port)
    local ports = EXPECTED_PORT[proto]
    if not ports then return true end
    for _, p in ipairs(ports) do
        if p == port then return true end
    end
    return false
end

local function decode(port, raw)
    local info = { banner = "", protocol = "", product = "", version = "",
        confidence = 0.0, mismatch = false }

    if is_tls(raw) then
        local ver = { [1] = "1.0", [2] = "1.1", [3] = "1.2", [4] = "1.3" }
        local b3 = raw:byte(3)
        info.protocol = "tls"
        info.product = "TLS"
        info.banner = "TLS " .. (ver[b3] or "?") .. " handshake"
        info.confidence = 0.90
        return info
    end

    local mysql = decode_mysql(raw)
    if mysql then
        info.protocol, info.product, info.version = "mysql", "MySQL", mysql
        info.banner = "MySQL " .. mysql
        info.confidence = 0.98
        return info
    end

    local text = sanitize(raw)
    if text:sub(1, 4) == "SSH-" then
        local line = first_line(text)
        local product, version = line:match("^SSH%-%d+%.%d+%-([%w%.]+)_([%w%.]+)")
        info.protocol, info.product, info.version = "ssh", product or "SSH", version or ""
        info.banner = line
        info.confidence = 0.99
        return info
    end

    if text:sub(1, 4) == "RFB " then
        local line = first_line(text)
        info.protocol, info.product = "vnc", "VNC"
        info.version = line:sub(5)
        info.banner = line
        info.confidence = 0.97
        return info
    end

    if raw:match("^[%+%-%:%$%*]") and raw:find("\r\n", 1, true) then
        local version = text:match("redis_version:([%d%.]+)") or ""
        info.protocol, info.product, info.version = "redis", "Redis", version
        info.banner = version ~= "" and ("Redis " .. version) or first_line(text)
        info.confidence = 0.95
        return info
    end

    if #raw >= 16 then
        local opcode = raw:byte(13) + raw:byte(14) * 256 + raw:byte(15) * 65536 + raw:byte(16) * 16777216
        if opcode == 1 or opcode == 2004 or opcode == 2013 then
            info.protocol, info.product = "mongodb", "MongoDB"
            info.banner = "MongoDB"
            info.confidence = 0.93
            return info
        end
    end

    if raw:sub(1, 16):find("SMB", 1, true) then
        info.protocol, info.product = "smb", "SMB"
        info.banner = "SMB"
        info.confidence = 0.95
        return info
    end

    local b1, b2 = raw:byte(1, 2)
    if b1 == 3 and b2 == 0 and #raw >= 11 then
        info.protocol, info.product = "rdp", "RDP"
        info.banner = "RDP (X.224 negotiation)"
        info.confidence = 0.88
        return info
    end

    if raw:sub(1, 4) == "AMQP" then
        info.protocol, info.product = "amqp", "RabbitMQ"
        info.banner = "AMQP connection.start"
        info.confidence = 0.95
        return info
    end

    if b1 == 0x20 and b2 == 0x02 then
        info.protocol, info.product = "mqtt", "MQTT"
        info.banner = "MQTT CONNACK"
        info.confidence = 0.90
        return info
    end

    if text:match("^HTTP/%d%.%d%s+%d%d%d") then
        return decode_http(text, false)
    end

    local low = text:lower()
    for _, rule in ipairs(TEXT_RULES) do
        for _, needle in ipairs(rule.needles) do
            if low:find(needle, 1, true) then
                local conf = rule.conf
                info.protocol, info.product, info.confidence = rule.proto, rule.product, conf
                local lines = {}
                for line in text:gmatch("[^\r\n]+") do
                    line = line:gsub("^%s+", ""):gsub("%s+$", "")
                    if #line > 0 then lines[#lines + 1] = line end
                    if #lines >= 2 then break end
                end
                info.banner = truncate(table.concat(lines, " | "), 220)
                return info
            end
        end
    end

    if #text > 0 then
        info.protocol = "unknown"
        info.banner = truncate(text, 220)
        info.confidence = 0.30
    end
    return info
end

local function finalize(info, port)
    info.banner = truncate(info.banner or "", 260)
    if info.protocol ~= "" and not port_is_expected(info.protocol, port) then
        info.mismatch = true
        if info.confidence > 0.55 then info.confidence = info.confidence - 0.05 end
    end
    if info.confidence == 0 and #info.banner > 0 then info.confidence = 0.4 end
    return info
end

-- ── public probe API ─────────────────────────────────────────────

function ProbeRunner:probe(host, port)
    port = tonumber(port)
    local best = nil
    for _, stage in ipairs(self:build_plan(host, port)) do
        local client = self:tcp_connect(host, port, PROBE_WAIT)
        if client then
            if stage.payload then
                client:send(stage.payload)
            end
            local raw = read_until_quiet(client, stage.settle)
            client:close()
            if #raw > 0 then
                local info = decode(port, raw)
                info.evidence = stage.name
                if not best or info.confidence > best.confidence
                    or (info.confidence == best.confidence and #info.banner > #best.banner) then
                    best = info
                end
                if best and best.confidence >= 0.80 then break end
            end
        end
    end
    if not best then
        return { banner = "", protocol = "", product = "", version = "",
            confidence = 0, evidence = "no-response", mismatch = false }
    end
    return finalize(best, port)
end

-- Legacy per-protocol helpers kept for callers that still use them.

function ProbeRunner:probe_http(host, port)
    return self:probe(host, port)
end

function ProbeRunner:probe_ssh(host, port)
    return self:probe(host, port)
end

function ProbeRunner:probe_ftp(host, port)
    return self:probe(host, port)
end

function ProbeRunner:probe_smtp(host, port)
    return self:probe(host, port)
end

function ProbeRunner:probe_generic(host, port)
    return self:probe(host, port)
end

function ProbeRunner:run_probe(host, port, _probe_type)
    return self:probe(host, port)
end

function ProbeRunner:match_pattern(text, pattern, kind)
    kind = kind or "contains"
    if kind == "contains" then
        return text:find(pattern, 1, true) ~= nil
    elseif kind == "prefix" then
        return text:sub(1, #pattern) == pattern
    elseif kind == "regex" then
        local ok, result = pcall(function() return text:match(pattern) end)
        return ok and result ~= nil
    end
    return false
end

function ProbeRunner:score_match(hits, label, weight)
    for _, h in ipairs(hits) do
        if h.label == label then
            h.score = h.score + weight
            return
        end
    end
    table.insert(hits, { label = label, score = weight })
end

local function create_runner()
    return ProbeRunner.new()
end

local function run_http_probe(host, port)
    return ProbeRunner.new():probe(host, port)
end

local function run_ssh_probe(host, port)
    return ProbeRunner.new():probe(host, port)
end

return {
    ProbeRunner = ProbeRunner,
    create_runner = create_runner,
    run_http_probe = run_http_probe,
    run_ssh_probe = run_ssh_probe,
    version = "3.1.0",
}
