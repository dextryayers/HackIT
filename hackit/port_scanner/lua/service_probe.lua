local socket = require("socket")
local json = require("json")

local plugin = {
    name = "Advanced Service Probe",
    version = "1.0.0",
    description = "Protocol-specific probes for SMTP, POP3, IMAP, FTP, SSH, Redis, MongoDB, MySQL, PostgreSQL with banner grabbing and timing",
    author = "HackIT Team"
}

local service_probes = {
    smtp = {
        probes = {
            { data = "EHLO hackit.local\r\n", name = "EHLO" },
            { data = "HELO hackit.local\r\n", name = "HELO" },
            { data = "VRFY root\r\n", name = "VRFY" },
            { data = "EXPN root\r\n", name = "EXPN" }
        },
        port = 25
    },
    pop3 = {
        probes = {
            { data = "CAPA\r\n", name = "CAPA" },
            { data = "USER test\r\n", name = "USER" },
            { data = "STAT\r\n", name = "STAT" },
            { data = "LIST\r\n", name = "LIST" }
        },
        port = 110
    },
    imap = {
        probes = {
            { data = "A001 CAPABILITY\r\n", name = "CAPABILITY" },
            { data = "A002 LOGIN test test\r\n", name = "LOGIN" },
            { data = "A003 LIST \"\" \"*\"\r\n", name = "LIST" }
        },
        port = 143
    },
    ftp = {
        probes = {
            { data = "SYST\r\n", name = "SYST" },
            { data = "FEAT\r\n", name = "FEAT" },
            { data = "PWD\r\n", name = "PWD" },
            { data = "STAT\r\n", name = "STAT" },
            { data = "HELP\r\n", name = "HELP" }
        },
        port = 21
    },
    ssh = {
        probes = {
            { data = "SSH-2.0-HackITClient_1.0\r\n", name = "SSH banner" },
            { data = "\r\n", name = "Empty line" }
        },
        port = 22
    },
    redis = {
        probes = {
            { data = "PING\r\n", name = "PING" },
            { data = "INFO\r\n", name = "INFO" },
            { data = "CONFIG GET *\r\n", name = "CONFIG" },
            { data = "SLAVEOF NO ONE\r\n", name = "SLAVEOF" }
        },
        port = 6379
    },
    mongodb = {
        probes = {
            { data = string.char(0x3a, 0x00, 0x00, 0x00) .. -- length
                     string.char(0x00, 0x00, 0x00, 0x00) .. -- requestID
                     string.char(0x00, 0x00, 0x00, 0x00) .. -- responseTo
                     string.char(0xd4, 0x07, 0x00, 0x00) .. -- opCode
                     string.char(0x00, 0x00, 0x00, 0x00) .. -- flags
                     string.char(0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64) .. "\x00" .. -- fullCollectionName
                     string.char(0x00, 0x00, 0x00, 0x00) .. -- numToSkip
                     string.char(0x00, 0x00, 0x00, 0x00) .. -- numToReturn
                     "{\"ping\":1}\x00",
              name = "ping" }
        },
        port = 27017
    },
    mysql = {
        probes = {
            { data = "", name = "Banner grab" },
            { data = string.char(0x0a) .. "SELECT 1",
              name = "Auth test" }
        },
        port = 3306
    },
    postgresql = {
        probes = {
            { data = string.char(0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f),
              name = "SSLRequest" }
        },
        port = 5432
    }
}

local function detect_service_from_port(port)
    for svc_name, svc_info in pairs(service_probes) do
        if svc_info.port == port then
            return svc_name, svc_info
        end
    end
    return nil, nil
end

local function send_probe(target, port, data, timeout_sec)
    local sock = socket.tcp()
    sock:settimeout(timeout_sec or 3000)
    sock:setoption("keepalive", true)

    local start_time = socket.gettime()

    local ok, err = sock:connect(target, port)
    if not ok then
        sock:close()
        return nil, nil, err
    end

    local initial_banner, recv_err = sock:receive("*l")
    if not initial_banner then
        initial_banner = ""
    end

    if data and #data > 0 then
        local send_ok, send_err = sock:send(data)
        if not send_ok then
            sock:close()
            return initial_banner, nil, send_err
        end
    end

    sock:settimeout(2000)
    local response_lines = {}
    for i = 1, 30 do
        local line, line_err = sock:receive("*l")
        if line then
            table.insert(response_lines, line)
        else
            break
        end
    end

    sock:close()

    local elapsed = socket.gettime() - start_time

    return initial_banner, response_lines, nil, elapsed
end

local function analyze_smtp(target, port, opts)
    local findings = {}
    local risk_score = 0
    local elapsed_total = 0

    table.insert(findings, "SMTP Probe Analysis for " .. target .. ":" .. port)

    local initial_banner, _, _, elapsed = send_probe(target, port, "", 3000)
    if initial_banner then
        table.insert(findings, "SMTP Server: " .. initial_banner:sub(1, 150))
        elapsed_total = elapsed_total + (elapsed or 0)
    end

    for _, probe in ipairs(service_probes.smtp.probes) do
        local _, responses, err, p_elapsed = send_probe(target, port, probe.data, 2000)
        elapsed_total = elapsed_total + (p_elapsed or 0)
        if responses and #responses > 0 then
            for _, line in ipairs(responses) do
                table.insert(findings, probe.name .. " response: " .. line:sub(1, 150))
                if line:find("250-AUTH") or line:find("250 AUTH") then
                    table.insert(findings, "SMTP AUTH supported")
                    risk_score = math.min(100, risk_score + 10)
                end
                if line:find("250-STARTTLS") then
                    table.insert(findings, "SMTP STARTTLS supported")
                end
                if line:find("250%-VRFY") or line:find("250 VRFY") then
                    table.insert(findings, "SMTP VRFY enabled (user enumeration)")
                    risk_score = math.min(100, risk_score + 15)
                end
                if line:find("250%-EXPN") or line:find("250 EXPN") then
                    table.insert(findings, "SMTP EXPN enabled (user enumeration)")
                    risk_score = math.min(100, risk_score + 15)
                end
                if line:find("250%-SIZE") then
                    local max_size = line:match("SIZE (%d+)")
                    if max_size then
                        table.insert(findings, "SMTP max message size: " .. max_size .. " bytes")
                    end
                end
                if line:find("250%-PIPELINING") then
                    table.insert(findings, "SMTP PIPELINING supported")
                end
                if line:find("250%-CHUNKING") then
                    table.insert(findings, "SMTP CHUNKING (BDAT) supported")
                end
                if line:find("250%-DSN") then
                    table.insert(findings, "SMTP DSN (Delivery Status Notification) supported")
                end
            end
        end
        if err then
            table.insert(findings, probe.name .. " error: " .. err)
        end
    end

    table.insert(findings, string.format("SMTP response time: %.2fms", elapsed_total * 1000))
    return findings, risk_score
end

local function analyze_ftp(target, port, opts)
    local findings = {}
    local risk_score = 0

    table.insert(findings, "FTP Probe Analysis for " .. target .. ":" .. port)

    local initial_banner, _, _, elapsed = send_probe(target, port, "", 3000)
    if initial_banner then
        table.insert(findings, "FTP Server: " .. initial_banner:sub(1, 150))
    end

    for _, probe in ipairs(service_probes.ftp.probes) do
        local _, responses, err, p_elapsed = send_probe(target, port, probe.data, 2000)
        if responses and #responses > 0 then
            for _, line in ipairs(responses) do
                table.insert(findings, probe.name .. " response: " .. line:sub(1, 150))
                if probe.name == "SYST" and line:find("215") then
                    local os_type = line:match("215 (.+)")
                    if os_type then
                        table.insert(findings, "FTP server OS: " .. os_type)
                    end
                end
                if probe.name == "FEAT" then
                    if line:find("AUTH TLS") then
                        table.insert(findings, "FTP over TLS supported")
                    end
                    if line:find("AUTH SSL") then
                        table.insert(findings, "FTP over SSL supported")
                    end
                end
            end
        end
        if err then
            table.insert(findings, probe.name .. " error: " .. err)
        end
    end

    if initial_banner then
        if initial_banner:find("vsFTPd") and initial_banner:find("2%.3%.4") then
            table.insert(findings, "CRITICAL: vsFTPd 2.3.4 backdoor detected (CVE-2011-0762)")
            risk_score = math.min(100, risk_score + 95)
        end
        if initial_banner:find("ProFTPD") then
            table.insert(findings, "ProFTPD detected - monitor for known exploits")
            risk_score = math.min(100, risk_score + 10)
        end
        if initial_banner:find("Anonymous") or initial_banner:find("anonymous") then
            table.insert(findings, "Anonymous FTP access might be available")
            risk_score = math.min(100, risk_score + 20)
        end
    end

    table.insert(findings, string.format("FTP response time: %.2fms", (elapsed or 0) * 1000))
    return findings, risk_score
end

local function analyze_ssh(target, port, opts)
    local findings = {}
    local risk_score = 0

    table.insert(findings, "SSH Probe Analysis for " .. target .. ":" .. port)

    local initial_banner, _, _, elapsed = send_probe(target, port, "", 3000)
    if initial_banner then
        table.insert(findings, "SSH Server: " .. initial_banner:sub(1, 150))
        if initial_banner:find("OpenSSH") then
            local ver = initial_banner:match("OpenSSH_([%d.]+)")
            if ver then
                table.insert(findings, "OpenSSH version: " .. ver)
            end
        end
        if initial_banner:find("dropbear") then
            table.insert(findings, "Dropbear SSH detected")
        end
    end

    local _, responses, _, _ = send_probe(target, port, "SSH-2.0-HackITClient_1.0\r\n", 2000)
    if responses and #responses > 0 then
        for _, line in ipairs(responses) do
            table.insert(findings, "Banner exchange: " .. line:sub(1, 150))
        end
    end

    table.insert(findings, string.format("SSH response time: %.2fms", (elapsed or 0) * 1000))
    return findings, risk_score
end

local function analyze_redis(target, port, opts)
    local findings = {}
    local risk_score = 0

    table.insert(findings, "Redis Probe Analysis for " .. target .. ":" .. port)

    local initial_banner, _, _, elapsed = send_probe(target, port, "PING\r\n", 2000)
    if initial_banner then
        table.insert(findings, "Redis response: " .. initial_banner:sub(1, 150))
        if initial_banner:find("PONG") or initial_banner:find("+PONG") then
            table.insert(findings, "Redis server is responding (unauthenticated)")
            risk_score = math.min(100, risk_score + 30)
        end
        if initial_banner:find("NOAUTH") then
            table.insert(findings, "Redis requires authentication")
        end
    end

    local _, responses, _, _ = send_probe(target, port, "INFO\r\n", 2000)
    if responses and #responses > 0 then
        for _, line in ipairs(responses) do
            if line:find("redis_version") then
                table.insert(findings, "Redis info: " .. line:sub(1, 150))
            end
            if line:find("os:") then
                table.insert(findings, "Redis OS: " .. line:sub(1, 100))
            end
            if line:find("uptime_in_seconds") then
                table.insert(findings, "Redis info: " .. line:sub(1, 150))
            end
        end
    end

    table.insert(findings, string.format("Redis response time: %.2fms", (elapsed or 0) * 1000))
    return findings, risk_score
end

local function analyze_mysql(target, port, opts)
    local findings = {}
    local risk_score = 0

    table.insert(findings, "MySQL Probe Analysis for " .. target .. ":" .. port)

    local initial_banner, _, _, elapsed = send_probe(target, port, "", 3000)
    if initial_banner then
        table.insert(findings, "MySQL Server: " .. initial_banner:sub(1, 150))
        if initial_banner:find("mysql") then
            table.insert(findings, "MySQL detected")
        end
        if initial_banner:find("MariaDB") then
            table.insert(findings, "MariaDB detected")
        end
    end

    table.insert(findings, string.format("MySQL response time: %.2fms", (elapsed or 0) * 1000))
    return findings, risk_score
end

local function analyze_postgresql(target, port, opts)
    local findings = {}
    local risk_score = 0

    table.insert(findings, "PostgreSQL Probe Analysis for " .. target .. ":" .. port)

    local initial_banner, _, _, elapsed = send_probe(target, port, "", 3000)
    if initial_banner then
        table.insert(findings, "PostgreSQL Server: " .. initial_banner:sub(1, 150))
    end

    local _, responses, _, _ = send_probe(target, port,
        string.char(0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f), 2000)
    if responses and #responses > 0 then
        for _, line in ipairs(responses) do
            table.insert(findings, "PostgreSQL SSL response: " .. line:sub(1, 150))
        end
    end

    table.insert(findings, string.format("PostgreSQL response time: %.2fms", (elapsed or 0) * 1000))
    return findings, risk_score
end

local function analyze_generic(target, port, banner, opts)
    local findings = {}
    local risk_score = 0
    local elapsed_total = 0

    table.insert(findings, "Generic service probe for " .. target .. ":" .. port)

    if banner and #banner > 0 then
        table.insert(findings, "Banner: " .. banner:sub(1, 200))
    end

    local _, responses, _, elapsed = send_probe(target, port, "\r\n\r\n", 2000)
    elapsed_total = elapsed_total + (elapsed or 0)
    if responses and #responses > 0 then
        for _, line in ipairs(responses) do
            table.insert(findings, "Response to probe: " .. line:sub(1, 150))
        end
    end

    local _, responses2, _, elapsed2 = send_probe(target, port, "GET / HTTP/1.0\r\n\r\n", 2000)
    elapsed_total = elapsed_total + (elapsed2 or 0)
    if responses2 and #responses2 > 0 then
        for _, line in ipairs(responses2) do
            table.insert(findings, "HTTP probe: " .. line:sub(1, 150))
            if line:find("HTTP/") then
                table.insert(findings, "Service identified as HTTP")
            end
        end
    end

    table.insert(findings, string.format("Generic response time: %.2fms", elapsed_total * 1000))
    return findings, risk_score
end

function plugin.run(target, port, banner, opts)
    opts = opts or {}
    local findings = {}
    local risk_score = 0

    local svc_name, svc_info = detect_service_from_port(port)
    if not svc_name then
        local generic_findings, generic_risk = analyze_generic(target, port, banner, opts)
        for _, f in ipairs(generic_findings) do table.insert(findings, f) end
        risk_score = math.min(100, risk_score + generic_risk)
    else
        local analyzer_map = {
            smtp = analyze_smtp,
            pop3 = analyze_smtp,
            imap = analyze_smtp,
            ftp = analyze_ftp,
            ssh = analyze_ssh,
            redis = analyze_redis,
            mongodb = analyze_mysql,
            mysql = analyze_mysql,
            postgresql = analyze_postgresql
        }

        local analyzer = analyzer_map[svc_name]
        if analyzer then
            local svc_findings, svc_risk = analyzer(target, port, opts)
            for _, f in ipairs(svc_findings) do table.insert(findings, f) end
            risk_score = math.min(100, risk_score + svc_risk)
        else
            local generic_findings, generic_risk = analyze_generic(target, port, banner, opts)
            for _, f in ipairs(generic_findings) do table.insert(findings, f) end
            risk_score = math.min(100, risk_score + generic_risk)
        end
    end

    return {
        status = "completed",
        findings = findings,
        risk_score = risk_score
    }
end

return plugin
