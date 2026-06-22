local stdnse = require "stdnse"
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
