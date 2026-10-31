local stdnse = require "stdnse"
local tls = require "tls"
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

description = [[Tests for the Heartbleed vulnerability (CVE-2014-0160) by sending a malformed heartbeat request and checking for a response containing leaked memory. Uses multiple probes and payload sizes for reliable detection.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function try_heartbleed(host, port, protocol, payload_len)
    local sock = new_socket()
    sock:set_timeout(10000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return nil end
        local hello = tls.client_hello(protocol)
        sock:send(hello)
        local _, data = sock:receive_buf(tls.server_hello_done, 8000)
        if not data then return nil end
        local heartbeat = tls.heartbeat_request(payload_len)
        sock:send(heartbeat)
        local status2, resp = sock:receive_buf(tls.heartbeat_response, 5000)
        sock:close()
        if status2 and resp then
            return {len = #resp, data = resp}
        end
        return nil
    end)
    if not ok then
        pcall(function() sock:close() end)
    end
    return result
end

action = function(host, port)
    local protocols = {"TLSv1.2", "TLSv1.1", "TLSv1.0"}
    local function build_payloads(host)
    local items = {0x4000, 0x1000, 0x2000
    }
    return items
end
    local max_leak = 0
    for _, proto in ipairs(protocols) do
        for _, plen in ipairs(build_payloads(host)) do
            local resp = try_heartbleed(host, port, proto, plen)
            if resp and resp.len > 0 then
                max_leak = math.max(max_leak, resp.len)
            end
        end
    end
    if max_leak > 100 then
        local result = output_table()
        result.vulnerability = "CVE-2014-0160"
        result.name = "Heartbleed"
        result.affected = true
        result.bytes_leaked = max_leak
        result.severity = "CRITICAL"
        return result
    end
    return format_output(false, "Not vulnerable to Heartbleed")
end
