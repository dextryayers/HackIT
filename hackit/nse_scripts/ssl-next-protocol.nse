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

description = [[Checks for Next Protocol Negotiation (NPN) support by sending a TLS Client Hello with the NPN extension and parsing the server's response for negotiated protocols. Uses multiple TLS versions and structured output.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local npn_protocols = {"http/1.1", "spdy/3.1", "spdy/3", "spdy/2", "h2"}

action = function(host, port)
    local all_negotiated = {}
    for _, proto in ipairs({"TLSv1.2", "TLSv1.1", "TLSv1.0"}) do
        local sock = new_socket()
        sock:set_timeout(10000)
        local ok, data = pcall(function()
            local status = sock:connect(host.ip, port)
            if not status then return nil end
            local hello = tls.client_hello(proto, {npn = npn_protocols})
            sock:send(hello)
            local _, d = sock:receive_buf(tls.server_hello_done, 8000)
            sock:close()
            return d
        end)
        if not ok then
            pcall(function() sock:close() end)
        end
        if data then
            for _, npn in ipairs(npn_protocols) do
                if match(data, npn) then
                    all_negotiated[npn] = true
                end
            end
        end
    end
    if next(all_negotiated) then
        local result = output_table()
        result.npn_negotiated = {}
        for k in pairs(all_negotiated) do
            insert(result.npn_negotiated, k)
        end
        result.npn_supported = #result.npn_negotiated > 0
        return result
    end
    return format_output(false, "NPN not supported")
end
