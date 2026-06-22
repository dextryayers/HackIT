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

description = [[Checks whether TLS compression is enabled on the server by requesting DEFLATE compression in the Client Hello and seeing if it is accepted in the Server Hello. Uses multiple compression methods across TLS versions.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function test_compression_method(host, port, method)
    local sock = new_socket()
    sock:set_timeout(10000)
    local ok, data = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return nil end
        local hello = tls.client_hello("TLSv1.2", {compress = {method, "NULL"}})
        sock:send(hello)
        local _, d = sock:receive_buf(tls.server_hello_done, 8000)
        sock:close()
        return d
    end)
    if not ok then
        pcall(function() sock:close() end)
        return nil
    end
    return data
end

action = function(host, port)
    local methods = {"DEFLATE", "LZS", "BZIP2"}
    local detected = nil
    for _, method in ipairs(methods) do
        local data = test_compression_method(host, port, method)
        if data then
            if match(data, method) then
                detected = method
                break
            end
        end
    end
    local result = output_table()
    if detected then
        result.compression = detected
        result.status = "enabled"
    else
        result.compression = "NULL"
        result.status = "disabled"
    end
    return result
end
