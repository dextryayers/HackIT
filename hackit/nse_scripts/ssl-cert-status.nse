local stdnse = require "stdnse"
local sslcert = require "sslcert"
local os = require "os"
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

description = [[Checks SSL certificate revocation status by examining the certificate's validity period, comparing against current date, and checking for CRL/OCSP URLs. Extracts version info and provides structured output.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function parse_date(date_str)
    if not date_str then return nil end
    local y, m, d = match(date_str, "(%d%d%d%d)-(%d%d)-(%d%d)")
    if y and m and d then
        local ok, t = pcall(os.time, {year = tonumber(y), month = tonumber(m), day = tonumber(d)})
        if ok then return t end
    end
    local y2, m2, d2 = match(date_str, "(%d%d%d%d)/(%d+)/(%d+)")
    if y2 and m2 and d2 then
        local ok, t = pcall(os.time, {year = tonumber(y2), month = tonumber(m2), day = tonumber(d2)})
        if ok then return t end
    end
    return nil
end

action = function(host, port)
    local cert = sslcert.getCertificate(host, port)
    -- sslcert returns a non-table sentinel on some nmap builds; index only tables.
    if type(cert) ~= "table" then
        return format_output(false, "Could not fetch SSL certificate")
    end
    local result = output_table()
    result.subject = cert.subject
    result.issuer = cert.issuer
    local current_time = os.time()
    local not_before = parse_date(cert.validFrom)
    local not_after = parse_date(cert.validTo)
    if not_before and current_time < not_before then
        result.status = "NOT_YET_VALID"
        result.days_until_valid = math.floor((not_before - current_time) / 86400)
    elseif not_after and current_time > not_after then
        result.status = "EXPIRED"
        result.days_expired = math.floor((current_time - not_after) / 86400)
    elseif not_before and not_after then
        result.status = "VALID"
        result.days_remaining = math.floor((not_after - current_time) / 86400)
    else
        result.status = "UNKNOWN"
    end
    result.valid_from = cert.validFrom
    result.valid_to = cert.validTo
    if cert.serial then
        result.serial = cert.serial
    end
    if cert.crl_urls and #cert.crl_urls > 0 then
        result.crl_urls = cert.crl_urls
    end
    if cert.ocsp_urls and #cert.ocsp_urls > 0 then
        result.ocsp_urls = cert.ocsp_urls
    end
    if cert.pubkey then
        result.pubkey_algorithm = cert.pubkey.algorithm
        result.pubkey_bits = cert.pubkey.bits
    end
    local ver = cert.match(validFrom, "(%d%d%d%d)") or ""
    if ver ~= "" then
        result.certificate_year = ver
    end
    return result
end
