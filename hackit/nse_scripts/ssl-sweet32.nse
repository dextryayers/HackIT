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
        if data and (data:match("server_hello") or data:match("handshake")) then
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
