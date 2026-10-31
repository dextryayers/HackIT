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

description = [[Enumerates all supported SSL/TLS cipher suites by attempting to connect with each cipher and recording which are accepted. Uses multiple probes, version extraction, and structured output.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and (port.number == 443 or port.service == "https")
end

local function test_cipher(host, port, protocol, cipher)
    local sock = new_socket()
    sock:set_timeout(8000)
    local ok, err = pcall(function()
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
    return err
end

action = function(host, port)
    local protocols = {"TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3"}
    local ciphers_tls12 = {
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    }
    local result = output_table()
    for _, proto in ipairs(protocols) do
        local supported = {}
        for _, cipher in ipairs(ciphers_tls12) do
            if test_cipher(host, port, proto, cipher) then
                insert(supported, cipher)
            end
        end
        if #supported > 0 then
            result[proto] = supported
        end
    end
    local sock = new_socket()
    sock:set_timeout(5000)
    local ok = pcall(function()
        sock:connect(host.ip, port)
        local hello = tls.client_hello("TLSv1.2")
        sock:send(hello)
        local _, data = sock:receive_buf(tls.server_hello_done, 3000)
        if data then
            local ver = match(data, "version[%s=]+([%d%.]+)") or match(data, "TLS([%d%.]+)")
            if ver then result.server_version = ver end
        end
        sock:close()
    end)
    if not ok then pcall(function() sock:close() end) end
    if next(result) then
        return result
    end
    return format_output(false, "Could not enumerate ciphers")
end
