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

description = [[Tests for the CRIME attack (CVE-2012-4929) by checking if the server supports TLS compression, which allows attackers to recover secret data by observing compression ratios. Uses multiple compression methods and structured output.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function test_compression(host, port, proto, method)
    local sock = new_socket()
    sock:set_timeout(8000)
    local ok, data = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return nil end
        local hello = tls.client_hello(proto, {compress = {method}})
        sock:send(hello)
        local _, d = sock:receive_buf(tls.server_hello_done, 5000)
        sock:close()
        return d
    end)
    if not ok then
        pcall(function() sock:close() end)
        return false
    end
    if data and (data:match(method) or data:match("compression")) then
        return true
    end
    return false
end

action = function(host, port)
    local methods = {"DEFLATE", "LZS", "NULL"}
    local found = {}
    for _, method in ipairs(methods) do
        for _, proto in ipairs({"TLSv1.2", "TLSv1.1", "TLSv1.0"}) do
            if test_compression(host, port, proto, method) then
                found[method] = true
            end
        end
    end
    if next(found) then
        local result = output_table()
        result.vulnerability = "CVE-2012-4929"
        result.name = "CRIME"
        result.affected = true
        result.methods = {}
        for k in pairs(found) do
            insert(result.methods, k)
        end
        result.severity = "MEDIUM"
        result.details = "TLS compression enabled - allows secret data recovery via compression ratio analysis"
        return result
    end
    return format_output(false, "Not vulnerable to CRIME (no TLS compression)")
end
