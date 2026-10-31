local stdnse = require "stdnse"
local tls = require "tls"
-- Lua 5.4 has no "bit" module; this is a 32-bit compatible replacement.
local bit = (function()
    local floor = math.floor
    local function toint(x) return floor(x) & 0xFFFFFFFF end
    local function fold(fn, a, ...)
        local r = toint(a)
        for i = 1, select("#", ...) do
            r = toint(fn(r, select(i, ...)))
        end
        return r
    end
    return {
        band = function(...) return fold(function(x, y) return x & y end, ...) end,
        bor = function(...) return fold(function(x, y) return x | y end, ...) end,
        bxor = function(...) return fold(function(x, y) return x ~ y end, ...) end,
        bnot = function(x) return (~toint(x)) & 0xFFFFFFFF end,
        lshift = function(x, n) return (toint(x) << (n & 31)) & 0xFFFFFFFF end,
        rshift = function(x, n) return toint(x) >> (n & 31) end,
        arshift = function(x, n) return toint(x) >> (n & 31) end,
        tobit = function(x) return toint(x) end,
        tohex = function(x) return format("%08x", toint(x)) end,
    }
end)()
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

description = [[Tests for the OpenSSL CCS injection vulnerability (CVE-2014-0224) by sending a premature ChangeCipherSpec message. Uses multiple TLS protocol versions and probes for reliable detection.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function build_ccs(version)
    local major, minor
    if version == "TLSv1.0" then major, minor = 0x03, 0x01
    elseif version == "TLSv1.1" then major, minor = 0x03, 0x02
    else major, minor = 0x03, 0x03 end
    return char(0x14, major, minor, 0x00, 0x01, 0x01)
end

action = function(host, port)
    local protocols = {"TLSv1.0", "TLSv1.1", "TLSv1.2"}
    for _, proto in ipairs(protocols) do
        local sock = new_socket()
        sock:set_timeout(10000)
        local ok, result = pcall(function()
            local status = sock:connect(host.ip, port)
            if not status then return end
            local hello = tls.client_hello(proto)
            sock:send(hello)
            local _, data = sock:receive_buf(tls.server_hello_done, 8000)
            if not data then sock:close(); return end
            sock:send(build_ccs(proto))
            local status2, resp = sock:receive_buf("\n", 3000)
            sock:close()
            if status2 and resp and #resp > 0 then
                return resp
            end
        end)
        if not ok then
            pcall(function() sock:close() end)
        end
        if result then
            local res = output_table()
            res.vulnerability = "CVE-2014-0224"
            res.name = "CCS Injection"
            res.affected = true
            res.protocol = proto
            res.severity = "HIGH"
            return res
        end
    end
    return format_output(false, "Not vulnerable to CCS Injection")
end
