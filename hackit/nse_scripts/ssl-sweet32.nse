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
local new_socket = nmap.new_socket
local resolve = nmap.resolve

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

description = [[Tests for the Sweet32 attack (CVE-2016-2183) by checking if the server supports 64-bit block cipher suites (3DES, Blowfish, IDEA) which are vulnerable to birthday bound attacks. Uses structured output with detected protocols and ciphers.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function test_64bit_cipher(host, port, protocol, cipher)
    local sock = new_socket()
    sock:set_timeout(8000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return false end
        local hello = tls.client_hello(protocol, {ciphers = {cipher}})
        sock:send(hello)
        local _, data = sock:receive_buf(tls.server_hello_done, 5000)
        sock:close()
        if data and (match(data, "server_hello") or match(data, "handshake")) then
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
    local weak_ciphers = {
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_RSA_WITH_IDEA_CBC_SHA",
        "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
    }
    local protocols = {"SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2"}
    local found = {}
    for _, proto in ipairs(protocols) do
        for _, cipher in ipairs(weak_ciphers) do
            if test_64bit_cipher(host, port, proto, cipher) then
                insert(found, proto .. ":" .. cipher)
            end
        end
    end
    if #found > 0 then
        local result = output_table()
        result.vulnerability = "CVE-2016-2183"
        result.name = "Sweet32"
        result.affected = true
        result.affected_ciphers = found
        result.severity = "MEDIUM"
        result.details = "64-bit block ciphers allow birthday bound collision attacks"
        return result
    end
    return format_output(false, "Not vulnerable to Sweet32")
end
