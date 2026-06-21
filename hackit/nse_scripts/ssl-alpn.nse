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

description = [[Enumerates supported Application-Layer Protocol Negotiation (ALPN) protocols by including an ALPN extension in the Client Hello and parsing the server response. Uses multiple TLS versions and structured output.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local alpn_protocols = {
    "http/1.1", "http/1.0", "h2", "h2c", "spdy/3.1", "spdy/3",
    "spdy/2", "webrtc", "stun.turn", "stun.nat-discovery",
    "coap", "xmpp-client", "xmpp-server", "acme-tls/1",
    "mqtt", "dns-over-tls", "smb2", "ocsp", "h3", "hq-interop",
}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function try_alpn(host, port, protocol)
    local sock = new_socket()
    sock:set_timeout(10000)
    local ok, data = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return nil end
        local hello = tls.client_hello(protocol, {alpn = alpn_protocols})
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
    local protocols = {"TLSv1.3", "TLSv1.2", "TLSv1.1"}
    local selected = {}
    local supported = {}
    for _, proto in ipairs(protocols) do
        local data = try_alpn(host, port, proto)
        if data then
            for _, alpn in ipairs(alpn_protocols) do
                if data:match(alpn) then
                    supported[alpn] = true
                end
            end
            local sel = data:match("alpn[^%w]*(%S+)") or data:match("selected[%s_]+protocol[%s:=]+([%w%./-]+)")
            if sel then
                selected[sel] = true
            end
        end
    end
    if next(supported) then
        local result = output_table()
        result.alpn_protocols = {}
        for k in pairs(supported) do
            insert(result.alpn_protocols, k)
        end
        result.selected = {}
        for k in pairs(selected) do
            insert(result.selected, k)
        end
        return result
    end
    return format_output(false, "No ALPN protocols detected or ALPN not supported")
end
