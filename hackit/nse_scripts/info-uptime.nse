local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Gathers system uptime info via SNMP, SMTP, or service-specific queries.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local function probe_smtp_uptime(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    local ok, resp = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local banner = socket:receive_bytes(128)
        socket:send("EHLO uptime\r\n")
        socket:receive_bytes(512)
        socket:send("HELP\r\n")
        local r = socket:receive_bytes(512)
        socket:send("STAT\r\n")
        local r2 = socket:receive_bytes(256)
        socket:close()
        return (r or "") .. (r2 or "")
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return resp
end

local function probe_http_uptime(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    local ok, resp = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        socket:send("GET / HTTP/1.1\r\nHost: " .. host.ip .. "\r\nConnection: close\r\n\r\n")
        local r = socket:receive_bytes(4096)
        socket:close()
        return r
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return resp
end

local function extract_uptime(text)
    if not text then return nil end
    local patterns = {
        "([%d]+:[%d]+:[%d]+)",
        "([%d]+) days",
        "([%d]+) hours",
        "up ([-%d]+ days)",
        "uptime:?%s*(.-)[\r\n]",
        "up (.-)[:,]",
        "([%d]+)d",
        "([%d]+)h",
    }
    for _, pat in ipairs(patterns) do
        local m = text:match(pat)
        if m then return m end
    end
    return nil
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local out = stdnse.output_table()
    out.service = "Uptime Detection"
    out.target = host.ip
    out.port = port.number
    local responses = {}
    local uptime_str = nil
    if port.number == 25 or port.number == 587 then
        local r = probe_smtp_uptime(host, port)
        if r then
            responses["SMTP"] = r:sub(1, 100)
            uptime_str = extract_uptime(r)
        end
    end
    if port.number == 80 or port.number == 8080 or port.number == 443 then
        local r = probe_http_uptime(host, port)
        if r then
            responses["HTTP"] = r:sub(1, 100)
            uptime_str = uptime_str or extract_uptime(r)
            local age = r:match("Age: (%d+)")
            if age then
                out.http_age_seconds = tonumber(age)
            end
        end
    end
    if not uptime_str then
        local socket = nmap.new_socket()
        socket:set_timeout(5000)
        local ok, r = pcall(function()
            local status, err = socket:connect(host, port)
            if not status then return nil end
            socket:send("UPTIME\r\n")
            local res = socket:receive_bytes(256)
            socket:close()
            return res
        end)
        if not ok then pcall(socket.close, socket) end
        if r then
            responses["Generic"] = r:sub(1, 100)
            uptime_str = uptime_str or extract_uptime(r)
        end
    end
    if responses then out.responses = responses end
    if uptime_str then
        out.status = "UPTIME_FOUND"
        out.uptime = uptime_str
    else
        out.status = "NOT_FOUND"
        out.message = "Could not determine uptime"
    end
    return out
end
