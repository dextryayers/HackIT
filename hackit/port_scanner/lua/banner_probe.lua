--[[
    banner_probe.lua — per-port protocol-accurate banner capture.

    Runs inside the Go Lua sandbox, so sockets come from the injected
    connect/send/receive/close/grab_banner functions. Every probe is
    port-aware: the payload matches the service that normally lives there, and
    the decoder reports what actually answered.

    Returns a one-line summary: "protocol product version (conf) banner"
]]

local MAX_BYTES = 8192
local IDLE_MS = 120

local function trim(s)
    return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function first_line(s)
    return trim(s:match("^[^\r\n]*") or "")
end

local function sanitize(s)
    return (s:gsub("[^\9\10\13\32-\126]", ""))
end

local function truncate(s, n)
    s = s:gsub("%s+", " ")
    if #s <= n then return s end
    return s:sub(1, n) .. "..."
end

local function http_req(host, port, path)
    path = path or "/"
    return string.format(
        "GET %s HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: HackIT-Lua/3.1\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        path, host, port
    )
end

-- Ordered payload plan per port. nil payload means "read first".
local function plan_for(port, host)
    local plan = {}
    local function add(name, payload, wait)
        plan[#plan + 1] = { name = name, payload = payload, wait = wait or 900 }
    end

    local greeting = {
        [21] = true, [22] = true, [23] = true, [25] = true, [110] = true,
        [143] = true, [445] = true, [465] = true, [587] = true, [873] = true,
        [993] = true, [995] = true, [1521] = true, [3306] = true,
        [3389] = true, [5432] = true, [5900] = true, [6379] = true,
        [9042] = true, [11211] = true, [27017] = true,
    }
    if greeting[port] then add("greeting", nil, 450) end

    if port == 25 or port == 465 or port == 587 then
        add("smtp", "EHLO hackit.local\r\n")
    elseif port == 110 then
        add("pop3", "CAPA\r\n")
    elseif port == 143 then
        add("imap", "a1 CAPABILITY\r\n")
    elseif port == 21 then
        add("ftp", "FEAT\r\n")
    elseif port >= 5432 and port <= 5440 then
        add("postgres", string.char(0, 0, 0, 8, 4, 210, 22, 47))
    elseif port >= 6379 and port <= 6385 then
        add("redis", "INFO server\r\n")
    elseif port >= 27017 and port <= 27025 then
        add("mongodb", "\63\0\0\0\1\0\0\0\0\0\0\0\212\7\0\0\0\0\0\0admin.$cmd\0\0\0\0\0\0\0\0\0\255\255\255\255\19\0\0\0\16ismaster\0\1\0\0\0\0")
    elseif port >= 5900 and port <= 5910 then
        add("vnc", "RFB 003.008\n")
    elseif port >= 3389 and port <= 3392 then
        add("rdp", string.char(3, 0, 0, 19, 14, 224, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0))
    elseif port == 5672 then
        add("amqp", "AMQP\0\0\9\1")
    elseif port == 1883 then
        add("mqtt", string.char(16, 14, 0, 4, 77, 81, 84, 84, 4, 0, 0, 0, 0, 0, 0, 0))
    elseif port == 11211 then
        add("memcached", "stats\r\n")
    elseif port == 873 then
        add("rsync", "@RSYNCD: 31.0\n")
    elseif port == 2181 then
        add("zookeeper", "srvr")
    elseif port == 445 then
        add("smb", "\0\0\0\0\254SMB\64\0\4\0\1\0\0\0\0\0\0\0\0\0" ..
            string.rep("\0", 20) .. string.char(2, 2, 16, 2, 0, 3, 2, 3, 17, 3))
    end

    add("http", http_req(host, port))
    add("crlf", "\r\n", 400)
    return plan
end

local function read_all(conn, first_wait)
    local chunks = {}
    local total = 0
    local data = receive(conn, 4096, first_wait or 900)
    if not data or #data == 0 then return "" end
    chunks[#chunks + 1] = data
    total = #data
    while total < MAX_BYTES do
        local more = receive(conn, 4096, IDLE_MS)
        if not more or #more == 0 then break end
        chunks[#chunks + 1] = more
        total = total + #more
    end
    return table.concat(chunks)
end

local function decode(port, raw)
    local info = { protocol = "", product = "", version = "", banner = "", confidence = 0 }

    if #raw >= 5 then
        local b1, b2, b3 = raw:byte(1, 3)
        if b1 == 22 and b2 == 3 and b3 <= 4 then
            local names = { [1] = "1.0", [2] = "1.1", [3] = "1.2", [4] = "1.3" }
            info.protocol, info.product = "tls", "TLS"
            info.version = names[b3] or ""
            info.banner = "TLS " .. info.version .. " handshake"
            info.confidence = 0.90
            return info
        end
    end

    if #raw >= 6 then
        local b4, b5 = raw:byte(4, 5)
        if b4 == 0 and b5 == 10 then
            local rest = raw:sub(6)
            local stop = rest:find("\0", 1, true)
            if stop and stop > 1 and stop <= 64 then
                local version = rest:sub(1, stop - 1)
                if version:match("%d") then
                    info.protocol, info.product, info.version = "mysql", "MySQL", version
                    info.banner = "MySQL " .. version
                    info.confidence = 0.98
                    return info
                end
            end
        end
    end

    local text = sanitize(raw)
    if text:sub(1, 4) == "SSH-" then
        local line = first_line(text)
        local product, version = line:match("^SSH%-%d+%.%d+%-([%w%.]+)_([%w%.]+)")
        info.protocol, info.product, info.version = "ssh", product or "SSH", version or ""
        info.banner, info.confidence = line, 0.99
        return info
    end

    if text:sub(1, 4) == "RFB " then
        local line = first_line(text)
        info.protocol, info.product = "vnc", "VNC"
        info.version, info.banner, info.confidence = line:sub(5), line, 0.97
        return info
    end

    if raw:match("^[%+%-%:%$%*]") and raw:find("\r\n", 1, true) then
        local version = text:match("redis_version:([%d%.]+)") or ""
        info.protocol, info.product, info.version = "redis", "Redis", version
        info.banner = version ~= "" and ("Redis " .. version) or first_line(text)
        info.confidence = 0.95
        return info
    end

    if text:match("^HTTP/%d%.%d%s+%d%d%d") then
        local parts = {}
        local product, version = "HTTP", ""
        for line in text:gmatch("[^\r\n]+") do
            local t = trim(line)
            if t:match("^HTTP/%d%.%d%s+%d%d%d") then
                parts[#parts + 1] = t
            else
                local server = t:match("^[Ss]erver:%s*(.+)$")
                if server then
                    parts[#parts + 1] = "Server: " .. server
                    local p, v = server:match("^([^/%s]+)/([^%s]+)")
                    if p then
                        product = p
                        version = v:gsub(";$", "")
                    else
                        local p2, v2 = server:match("^(%S+)%s+(%S+)")
                        product = p2 or server
                        if v2 and v2:match("%d+%.%d+") then version = v2:gsub(";$", "") end
                    end
                end
            end
            if #parts >= 5 then break end
        end
        local title = text:match("<[Tt][Ii][Tt][Ll][Ee][^>]*>(.-)</[Tt][Ii][Tt][Ll][Ee]>")
        if title and #title < 120 then
            parts[#parts + 1] = "Title: " .. title:gsub("%s+", " ")
        end
        info.protocol, info.product, info.version = "http", product, version
        info.banner = table.concat(parts, " | ")
        info.confidence = 0.95
        return info
    end

    if #raw >= 16 then
        local opcode = raw:byte(13) + raw:byte(14) * 256 + raw:byte(15) * 65536 + raw:byte(16) * 16777216
        if opcode == 1 or opcode == 2004 or opcode == 2013 then
            info.protocol, info.product = "mongodb", "MongoDB"
            info.banner, info.confidence = "MongoDB", 0.93
            return info
        end
    end

    if raw:sub(1, 16):find("SMB", 1, true) then
        info.protocol, info.product = "smb", "SMB"
        info.banner, info.confidence = "SMB", 0.95
        return info
    end

    if raw:sub(1, 4) == "AMQP" then
        info.protocol, info.product = "amqp", "RabbitMQ"
        info.banner, info.confidence = "AMQP connection.start", 0.95
        return info
    end

    local low = text:lower()
    local rules = {
        { "ftp", "FTP", { " 220 ", "vsftpd", "proftpd", "pure-ftpd" }, 0.92 },
        { "smtp", "SMTP", { "esmtp", "postfix", "exim", "sendmail" }, 0.90 },
        { "pop3", "POP3", { "+ok", "dovecot" }, 0.88 },
        { "imap", "IMAP", { "* ok", "dovecot", "cyrus" }, 0.88 },
        { "memcached", "Memcached", { "curr_items" }, 0.85 },
        { "rsync", "rsync", { "@rsyncd" }, 0.97 },
        { "elasticsearch", "Elasticsearch", { "you know, for search" }, 0.95 },
        { "prometheus", "Prometheus", { "# help", "# type" }, 0.85 },
        { "sip", "SIP", { "sip/2.0" }, 0.92 },
        { "rtsp", "RTSP", { "rtsp/1.0" }, 0.95 },
    }
    for _, rule in ipairs(rules) do
        for _, needle in ipairs(rule[3]) do
            if low:find(needle, 1, true) then
                info.protocol, info.product, info.confidence = rule[1], rule[2], rule[4]
                local lines = {}
                for line in text:gmatch("[^\r\n]+") do
                    line = trim(line)
                    if #line > 0 then lines[#lines + 1] = line end
                    if #lines >= 2 then break end
                end
                info.banner = truncate(table.concat(lines, " | "), 220)
                return info
            end
        end
    end

    if #text > 0 then
        info.protocol, info.banner, info.confidence = "unknown", truncate(text, 220), 0.30
    end
    return info
end

local function probe(host, port)
    if type(connect) ~= "function" then
        return nil
    end
    local best = nil
    for _, stage in ipairs(plan_for(port, host)) do
        local conn = connect(host, port, 900)
        if conn then
            if stage.payload then send(conn, stage.payload) end
            local raw = read_all(conn, stage.wait)
            close(conn)
            if #raw > 0 then
                local info = decode(port, raw)
                info.evidence = stage.name
                if not best or info.confidence > best.confidence then
                    best = info
                end
                if best and best.confidence >= 0.80 then break end
            end
        end
    end
    return best
end

function run_nse(host, port, service, banner)
    local port_num = tonumber(port) or 0
    local info = probe(host, port_num)

    if not info or #info.banner == 0 then
        if banner and #banner > 0 then
            return string.format("banner-only %s", truncate(sanitize(banner), 180))
        end
        return ""
    end

    return string.format(
        "%s %s %s (%.2f) %s",
        info.protocol ~= "" and info.protocol or "unknown",
        info.product ~= "" and info.product or "-",
        info.version ~= "" and info.version or "-",
        info.confidence or 0,
        info.banner
    )
end

function action()
    return run_nse(host, port, service, banner)
end

function run_precision_probe(h, p, b)
    local info = probe(h or host, tonumber(p or port) or 0)
    if not info then return "", "" end
    return info.product ~= "" and info.product or info.protocol, info.version
end

return true
