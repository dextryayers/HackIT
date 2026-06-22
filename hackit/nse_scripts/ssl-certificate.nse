local stdnse = require "stdnse"
local sslcert = require "sslcert"
local tls = require "tls"
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
