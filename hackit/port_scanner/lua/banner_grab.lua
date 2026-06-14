local socket = require("socket")
local ssl = require("ssl")
local http = require("socket.http")
local https = require("ssl.https")
local ltn12 = require("ltn12")
local json = require("json")

local plugin = {
    name = "Advanced Banner Grabbing",
    version = "1.0.0",
    description = "Multi-probe per protocol banner grabbing with TLS upgrade detection, HTTP/2 support check, protocol downgrade detection",
    author = "HackIT Team"
}

local probe_definitions = {
    http = {
        probes = {
            { data = "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: HackIT/1.0\r\nAccept: */*\r\n\r\n", name = "HTTP/1.1" },
            { data = "GET / HTTP/1.0\r\n\r\n", name = "HTTP/1.0" },
            { data = "HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n", name = "HEAD" },
            { data = "OPTIONS * HTTP/1.1\r\nHost: %s\r\n\r\n", name = "OPTIONS" },
            { data = "TRACE / HTTP/1.1\r\nHost: %s\r\n\r\n", name = "TRACE" }
        },
        timeout = 3000
    },
    https = {
        probes = {
            { data = "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: HackIT/1.0\r\nAccept: */*\r\n\r\n", name = "TLS+HTTP/1.1" },
            { data = "GET / HTTP/1.0\r\n\r\n", name = "TLS+HTTP/1.0" },
            { data = "HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n", name = "TLS+HEAD" }
        },
        timeout = 5000,
        tls = true
    },
    generic = {
        probes = {
            { data = "\r\n", name = "CRLF" },
            { data = "\n", name = "LF" },
            { data = "\r\n\r\n", name = "Double CRLF" },
            { data = "HELP\r\n", name = "HELP" },
            { data = "INFO\r\n", name = "INFO" },
            { data = "STATUS\r\n", name = "STATUS" }
        },
        timeout = 3000
    },
    tls = {
        probes = {
            { data = nil, name = "TLS handshake" },
            { data = "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", name = "TLS+HTTP/1.1" }
        },
        timeout = 5000,
        tls = true
    }
}

local function send_raw_probe(target, port, data, timeout_sec)
    local sock = socket.tcp()
    sock:settimeout(timeout_sec or 3000)

    local start = socket.gettime()
    local ok, err = sock:connect(target, port)
    if not ok then
        sock:close()
        return nil, nil, err, socket.gettime() - start
    end

    local initial_data
    sock:settimeout(1000)
    initial_data, _ = sock:receive("*l")

    if data and #data > 0 then
        local send_ok, send_err = sock:send(data)
        if not send_ok then
            sock:close()
            return initial_data, nil, send_err, socket.gettime() - start
        end
    end

    sock:settimeout(timeout_sec or 3000)
    local response_lines = {}
    for i = 1, 50 do
        local line, recv_err = sock:receive("*l")
        if line then
            table.insert(response_lines, line)
        else
            break
        end
    end

    local elapsed = socket.gettime() - start
    sock:close()
    return initial_data, response_lines, nil, elapsed
end

local function send_tls_probe(target, port, data, timeout_sec)
    local sock = socket.tcp()
    sock:settimeout(timeout_sec or 5000)

    local start = socket.gettime()
    local ok, err = sock:connect(target, port)
    if not ok then
        sock:close()
        return nil, nil, err, socket.gettime() - start
    end

    local params = {
        mode = "client",
        protocol = "tlsv1_2",
        verify = "none",
        options = "no_sslv2,no_sslv3"
    }

    local ssl_sock, ssl_err = ssl.wrap(sock, params)
    if not ssl_sock then
        sock:close()
        return nil, nil, ssl_err, socket.gettime() - start
    end

    local hand_ok, hand_err = pcall(ssl_sock.dohandshake, ssl_sock)
    if not hand_ok then
        ssl_sock:close()
        sock:close()
        return nil, nil, hand_err, socket.gettime() - start
    end

    local initial_data
    ssl_sock:settimeout(1000)
    initial_data, _ = ssl_sock:receive("*l")

    if data and #data > 0 then
        local send_ok, send_err = ssl_sock:send(data)
        if not send_ok then
            ssl_sock:close()
            sock:close()
            return initial_data, nil, send_err, socket.gettime() - start
        end
    end

    ssl_sock:settimeout(timeout_sec or 5000)
    local response_lines = {}
    for i = 1, 50 do
        local line, recv_err = ssl_sock:receive("*l")
        if line then
            table.insert(response_lines, line)
        else
            break
        end
    end

    local elapsed = socket.gettime() - start
    ssl_sock:close()
    sock:close()
    return initial_data, response_lines, nil, elapsed
end

local function detect_tls_upgrade(target, port)
    local findings = {}
    local sock = socket.tcp()
    sock:settimeout(3000)
    local ok, err = sock:connect(target, port)
    if not ok then
        sock:close()
        return findings, false
    end

    local data, _ = sock:receive("*l")
    if data then
        sock:send("GET / HTTP/1.1\r\nHost: " .. target .. "\r\n\r\n")
        sock:settimeout(2000)
        local headers = {}
        for i = 1, 20 do
            local line, _ = sock:receive("*l")
            if line then
                table.insert(headers, line)
                if line:find("Upgrade") or line:find("upgrade") then
                    table.insert(findings, "TLS upgrade: " .. line)
                end
            else
                break
            end
        end
        sock:close()
        return findings, true
    end
    sock:close()
    return findings, false
end

local function check_http2_support(target, port)
    local findings = {}
    local ok, result = pcall(function()
        local sock = socket.tcp()
        sock:settimeout(3000)
        sock:connect(target, port)

        local upgrade = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        sock:send(upgrade)
        sock:settimeout(2000)
        local response, _ = sock:receive("*l")
        sock:close()
        return response
    end)

    if ok and result then
        if result:find("HTTP/2") or result:find("h2") then
            table.insert(findings, "HTTP/2 supported")
        else
            table.insert(findings, "HTTP/2 not supported (" .. tostring(result):sub(1, 100) .. ")")
        end
    else
        table.insert(findings, "HTTP/2 check failed")
    end

    return findings
end

local function check_protocol_downgrade(target, port, banner)
    local findings = {}
    local risk_score = 0

    if banner then
        if banner:find("SSH") then
            local ver = banner:match("SSH%-(%d+%.%d+)")
            if ver and ver ~= "2.0" then
                table.insert(findings, "Protocol downgrade risk: SSH " .. ver .. " < 2.0")
                risk_score = 30
            end
        end
        if banner:find("HTTP/1%.0") then
            table.insert(findings, "Protocol downgrade risk: HTTP/1.0")
            risk_score = 10
        end
        if banner:find("SSLv") then
            table.insert(findings, "Protocol downgrade risk: SSL " .. (banner:match("SSLv(%d)") or "unknown"))
            risk_score = 40
        end
    end

    return findings, risk_score
end

function plugin.run(target, port, banner, opts)
    opts = opts or {}
    local findings = {}
    local risk_score = 0

    table.insert(findings, "Advanced banner grab for " .. target .. ":" .. port)

    if banner and #banner > 0 then
        table.insert(findings, "Initial banner: " .. banner:sub(1, 200))
    end

    local protocol_profiles = {}
    if port == 80 then
        protocol_profiles = { probe_definitions.http }
    elseif port == 443 then
        protocol_profiles = { probe_definitions.https, probe_definitions.tls }
    else
        if banner and (banner:find("HTTP") or banner:find("http")) then
            protocol_profiles = { probe_definitions.http }
        else
            protocol_profiles = { probe_definitions.generic }
        end
    end

    for _, profile in ipairs(protocol_profiles) do
        for _, probe in ipairs(profile.probes) do
            local probe_data = probe.data
            if probe_data and probe_data:find("%%s") then
                probe_data = probe_data:format(target)
            end

            local initial_resp, responses, err, elapsed
            if profile.tls then
                initial_resp, responses, err, elapsed = send_tls_probe(target, port, probe_data, profile.timeout)
            else
                initial_resp, responses, err, elapsed = send_raw_probe(target, port, probe_data, profile.timeout)
            end

            if initial_resp and #initial_resp > 0 then
                table.insert(findings, probe.name .. " initial: " .. initial_resp:sub(1, 150))
            end

            if responses and #responses > 0 then
                for _, line in ipairs(responses) do
                    table.insert(findings, probe.name .. " response: " .. line:sub(1, 150))
                end
            end

            if err then
                table.insert(findings, probe.name .. " error: " .. err)
            end

            table.insert(findings, string.format("%s time: %.2fms", probe.name, (elapsed or 0) * 1000))
        end
    end

    if port == 80 or port == 443 or (banner and banner:find("HTTP")) then
        local upgrade_findings, _ = detect_tls_upgrade(target, port)
        for _, uf in ipairs(upgrade_findings) do
            table.insert(findings, uf)
        end

        local h2_findings = check_http2_support(target, port)
        for _, hf in ipairs(h2_findings) do
            table.insert(findings, hf)
        end
    end

    local downgrade_findings, downgrade_risk = check_protocol_downgrade(target, port, banner)
    for _, df in ipairs(downgrade_findings) do
        table.insert(findings, df)
    end
    risk_score = math.min(100, risk_score + downgrade_risk)

    if #findings == 1 then
        table.insert(findings, "No banner data acquired from probes")
    end

    return {
        status = "completed",
        findings = findings,
        risk_score = risk_score
    }
end

return plugin
