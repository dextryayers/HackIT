local stdnse = require "stdnse"
local sslcert = require "sslcert"
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

description = [[Fetches and parses the SSL/TLS certificate from the server, extracting subject, issuer, validity dates, and fingerprint with version extraction and multiple probe attempts.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local cert = sslcert.getCertificate(host, port)
    if not cert then
        local sock = new_socket()
        sock:set_timeout(10000)
        local ok = sock:connect(host.ip, port)
        if not ok then
            local _, e = pcall(function() sock:close() end)
            return format_output(false, "Could not fetch SSL certificate")
        end
        local hellos = {
            tls.client_hello("TLSv1.2"),
            tls.client_hello("TLSv1.1"),
            tls.client_hello("TLSv1.0"),
        }
        local data
        for _, hello in ipairs(hellos) do
            local ok2, _ = pcall(function()
                sock:send(hello)
                local _, d = sock:receive_buf(tls.server_hello_done, 5000)
                data = d
            end)
            if ok2 and data then break end
        end
        pcall(function() sock:close() end)
        if not data then
            return format_output(false, "Could not fetch SSL certificate")
        end
        return format_output(false, "Certificate could not be parsed from handshake")
    end
    local result = output_table()
    result.subject = cert.subject
    result.issuer = cert.issuer
    result.valid_from = cert.validFrom
    result.valid_to = cert.validTo
    result.serial = cert.serial
    result.fingerprint_sha1 = cert.fingerprint
    if cert.pubkey then
        result.pubkey_algorithm = cert.pubkey.algorithm
        result.pubkey_bits = cert.pubkey.bits
        local ver = tostring(cert.pubkey.bits)
        if cert.pubkey.algorithm then
            ver = cert.pubkey.algorithm .. "_" .. (cert.pubkey.bits or "unknown")
        end
        result.pubkey_version = ver
    end
    if cert.san and #cert.san > 0 then
        result.subject_alt_names = cert.san
    end
    if cert.validTo then
        local year = cert.match(validTo, "(%d%d%d%d)")
        result.expiry_year = year
    end
    return result
end
