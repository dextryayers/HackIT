local stdnse = require "stdnse"
local nmap = require "nmap"
local shortport = require "shortport"



-- Fast-path bindings for the stdlib and nmap API used by this script.
-- Kept strict-mode safe: every name below is a declared local.
local format = string.format
local lower = string.lower
local upper = string.upper
local byte = string.byte
local sub = string.sub
local match = string.match
local gmatch = string.gmatch
local gsub = string.gsub
local find = string.find
local rep = string.rep
local char = string.char
local concat = table.concat
local insert = table.insert
local remove = table.remove
local sort = table.sort
local move = table.move
local tostring = tostring
local tonumber = tonumber
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local unpack = table.unpack
local setmetatable = setmetatable
local getmetatable = getmetatable
local error = error
local select = select

local clock = nmap.clock
local msleep = nmap.msleep

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    return nmap.msleep(math.max(0, math.floor(seconds * 1000)))
end

local strsplit = function(sep, str, max)
    local out, pos, n = {}, 1, 0
    if str == nil then return out end
    while true do
        if max and n >= max - 1 then
            out[#out + 1] = sub(str, pos)
            return out
        end
        local s, e = find(str, sep, pos)
        if not s then
            out[#out + 1] = sub(str, pos)
            return out
        end
        if e < pos then e = pos end
        out[#out + 1] = sub(str, pos, s - 1)
        pos = e + 1
        n = n + 1
        if pos > #str then
            out[#out + 1] = ""
            return out
        end
    end
end

local format_output = stdnse.format_output
local output_table = stdnse.output_table

description = [[Gathers system uptime info via SNMP, SMTP, or service-specific queries.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local function probe_smtp_uptime(host, port)
    local socket = new_socket()
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
    local socket = new_socket()
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
        local m = match(text, pat)
        if m then return m end
    end
    return nil
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local out = output_table()
    out.service = "Uptime Detection"
    out.target = host.ip
    out.port = port.number
    local responses = {}
    local uptime_str = nil
    if port.number == 25 or port.number == 587 then
        local r = probe_smtp_uptime(host, port)
        if r then
            responses["SMTP"] = sub(r, 1, 100)
            uptime_str = extract_uptime(r)
        end
    end
    if port.number == 80 or port.number == 8080 or port.number == 443 then
        local r = probe_http_uptime(host, port)
        if r then
            responses["HTTP"] = sub(r, 1, 100)
            uptime_str = uptime_str or extract_uptime(r)
            local age = match(r, "Age: (%d+)")
            if age then
                out.http_age_seconds = tonumber(age)
            end
        end
    end
    if not uptime_str then
        local socket = new_socket()
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
            responses["Generic"] = sub(r, 1, 100)
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
