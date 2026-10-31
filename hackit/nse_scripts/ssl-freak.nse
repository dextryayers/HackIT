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

description = [[Tests for the FREAK attack (CVE-2015-0204) by checking if the server accepts export-grade RSA cipher suites, allowing a man-in-the-middle to downgrade the connection. Uses structured output with CVE mapping.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function test_export_cipher(host, port, cipher)
    local sock = new_socket()
    sock:set_timeout(8000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return false end
        local hello = tls.client_hello("TLSv1.0", {ciphers = {cipher}})
        sock:send(hello)
        local _, data = sock:receive_buf(tls.server_hello_done, 5000)
        sock:close()
        if data then
            if match(data, "handshake_failure") or match(data, "insufficient_security") then
                return false
            end
            return true
        end
        return false
    end)
    if not ok then
        pcall(function() sock:close() end)
        return false
    end
    return result
end

action = function(host, port)
    local export_ciphers = {
        "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
        "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
        "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    }
    local found = {}
    for _, cipher in ipairs(export_ciphers) do
        if test_export_cipher(host, port, cipher) then
            insert(found, cipher)
        end
    end
    if #found > 0 then
        local result = output_table()
        result.vulnerability = "CVE-2015-0204"
        result.name = "FREAK"
        result.affected = true
        result.ciphers = found
        result.severity = "MEDIUM"
        result.details = "Server accepts export-grade RSA ciphers, allowing connection downgrade"
        return result
    end
    return format_output(false, "Not vulnerable to FREAK")
end
