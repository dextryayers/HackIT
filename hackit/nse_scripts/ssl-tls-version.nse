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

description = [[Tests which versions of SSL/TLS the server supports by attempting handshakes with each protocol version: SSLv2, SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, and TLSv1.3. Uses structured output with version string extraction.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function test_protocol(host, port, protocol)
    local sock = new_socket()
    sock:set_timeout(8000)
    local ok, data = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return false, nil end
        local hello
        if protocol == "SSLv2" then
            hello = char(0x80, 0x2e, 0x01, 0x03, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        else
            hello = tls.client_hello(protocol)
        end
        sock:send(hello)
        local status2, d = sock:receive_buf(tls.server_hello_done, 5000)
        sock:close()
        if status2 and d then
            local ver = d:match("version[%s:=]+([%d%.]+)") or d:match("(%u+)%-(%d%.?%d*)") or d:match("([%d%.]+)[%s]*-[%s]*server")
            return true, ver
        end
        return false, nil
    end)
    if not ok then
        pcall(function() sock:close() end)
        return false, nil
    end
    return ok, data
end

action = function(host, port)
    local protocol_list = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
    local result = output_table()
    for _, proto in ipairs(protocol_list) do
        local supported, version_str = test_protocol(host, port, proto)
        if supported then
            result[proto] = true
            if version_str then
                result[proto .. "_version"] = version_str
            end
        else
            result[proto] = false
        end
    end
    return result
end
