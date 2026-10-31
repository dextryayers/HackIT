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
local msleep = function(ms)
    if stdnse and stdnse.sleep then
        return stdnse.sleep((ms or 0) / 1000)
    end
    if nmap.msleep then
        return nmap.msleep(ms or 0)
    end
    local deadline = nmap.clock() + (ms or 0) / 1000
    while nmap.clock() < deadline do end
    return true
end
local new_socket = nmap.new_socket
local resolve = nmap.resolve

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    if stdnse and stdnse.sleep then
        return stdnse.sleep(seconds)
    end
    if nmap.msleep then
        return nmap.msleep(math.max(0, math.floor((seconds or 0) * 1000)))
    end
    local deadline = nmap.clock() + (seconds or 0)
    while nmap.clock() < deadline do end
    return true
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

description = [[Tests for the BEAST attack (CVE-2011-3389) by checking if the server supports TLSv1.0 with CBC mode ciphers and does not support TLSv1.1+. Uses structured output with version detection.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function test_protocol_version_cbc(host, port, protocol)
    local sock = new_socket()
    sock:set_timeout(8000)
    local ok = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return false end
        local hello = tls.client_hello(protocol, {
            ciphers = {
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                "TLS_RSA_WITH_AES_256_CBC_SHA",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            }
        })
        sock:send(hello)
        local _, data = sock:receive_buf(tls.server_hello_done, 5000)
        sock:close()
        return data ~= nil
    end)
    if not ok then
        pcall(function() sock:close() end)
    end
    return ok
end

action = function(host, port)
    local tls10_cbc = test_protocol_version_cbc(host, port, "TLSv1.0")
    local tls11 = test_protocol_version_cbc(host, port, "TLSv1.1")
    if tls10_cbc then
        local result = output_table()
        result.vulnerability = "CVE-2011-3389"
        result.name = "BEAST"
        result.affected = true
        result.tls10_cbc_supported = true
        result.tls11_or_higher_available = tls11
        if tls11 then
            result.severity = "LOW"
            result.details = "TLSv1.0 with CBC ciphers supported, but TLSv1.1+ is available (mitigation exists)"
        else
            result.severity = "MEDIUM"
            result.details = "TLSv1.0 with CBC ciphers supported, no TLSv1.1+ available"
        end
        return result
    end
    return format_output(false, "Not vulnerable to BEAST")
end
