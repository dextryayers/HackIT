local stdnse = require "stdnse"
local sslcert = require "sslcert"
local os = require "os"
local nmap = require "nmap"
local shortport = require "shortport"



-- nmp function cache
local nmap_register = nmap.register_script
local nmap_settitle = nmap.set_title
local nmap_resolve = nmap.resolve
local nmap_get_port_state = nmap.get_port_state
local nmap_set_port_state = nmap.set_port_state
local comm = nmap.comm
local new_socket = nmap.new_socket
local get_timeout = nmap.get_timeout

-- Performance optimizations
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
local move = table.move or function(a1, f, e, t, a2)
    if not a2 then a2 = a1 end
    for i = f, e do a2[t + i - f] = a1[i] end
    return a2
end
local tostring = tostring
local tonumber = tonumber
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local unpack = unpack or table.unpack
local setmetatable = setmetatable
local getmetatable = getmetatable
local error = error
local select = select
local clock = nmap.clock
local msleep = nmap.msleep
local sleep = stdnse.sleep
local strsplit = stdnse.strsplit
local format_output = stdnse.format_output
local output_table = stdnse.output_table

description = [[Checks SSL certificate revocation status by examining the certificate's validity period, comparing against current date, and checking for CRL/OCSP URLs. Extracts version info and provides structured output.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function parse_date(date_str)
    if not date_str then return nil end
    local y, m, d = date_str:match("(%d%d%d%d)-(%d%d)-(%d%d)")
    if y and m and d then
        local ok, t = pcall(os.time, {year = tonumber(y), month = tonumber(m), day = tonumber(d)})
        if ok then return t end
    end
    local y2, m2, d2 = date_str:match("(%d%d%d%d)/(%d+)/(%d+)")
    if y2 and m2 and d2 then
        local ok, t = pcall(os.time, {year = tonumber(y2), month = tonumber(m2), day = tonumber(d2)})
        if ok then return t end
    end
    return nil
end

action = function(host, port)
    local cert = sslcert.getCertificate(host, port)
    if not cert then
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
    local ver = cert.validFrom:match("(%d%d%d%d)") or ""
    if ver ~= "" then
        result.certificate_year = ver
    end
    return result
end
