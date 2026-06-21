local stdnse = require "stdnse"
local tls = require "tls"
local bit = require "bit"
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

description = [[Tests for the OpenSSL CCS injection vulnerability (CVE-2014-0224) by sending a premature ChangeCipherSpec message. Uses multiple TLS protocol versions and probes for reliable detection.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function build_ccs(version)
    local major, minor
    if version == "TLSv1.0" then major, minor = 0x03, 0x01
    elseif version == "TLSv1.1" then major, minor = 0x03, 0x02
    else major, minor = 0x03, 0x03 end
    return char(0x14, major, minor, 0x00, 0x01, 0x01)
end

action = function(host, port)
    local protocols = {"TLSv1.0", "TLSv1.1", "TLSv1.2"}
    for _, proto in ipairs(protocols) do
        local sock = new_socket()
        sock:set_timeout(10000)
        local ok, result = pcall(function()
            local status = sock:connect(host.ip, port)
            if not status then return end
            local hello = tls.client_hello(proto)
            sock:send(hello)
            local _, data = sock:receive_buf(tls.server_hello_done, 8000)
            if not data then sock:close(); return end
            sock:send(build_ccs(proto))
            local status2, resp = sock:receive_buf("\n", 3000)
            sock:close()
            if status2 and resp and #resp > 0 then
                return resp
            end
        end)
        if not ok then
            pcall(function() sock:close() end)
        end
        if result then
            local res = output_table()
            res.vulnerability = "CVE-2014-0224"
            res.name = "CCS Injection"
            res.affected = true
            res.protocol = proto
            res.severity = "HIGH"
            return res
        end
    end
    return format_output(false, "Not vulnerable to CCS Injection")
end
