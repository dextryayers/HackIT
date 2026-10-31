local stdnse = require "stdnse"
local tls = require "tls"
local nmap = require "nmap"
local shortport = require "shortport"



-- Fast-path bindings for the stdlib and nmap API used by this script.
-- Kept strict-mode safe: every name below is a declared local.
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
local move = table.move
local tostring = tostring
local tonumber = tonumber
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local unpack = table.unpack
local setmetatable = setmetatable
local getmetatable = getmetatable
local error = error
local select = select

local clock = nmap.clock
local msleep = nmap.msleep

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    return nmap.msleep(math.max(0, math.floor(seconds * 1000)))
end

local strsplit = function(sep, str, max)
    local out, pos, n = {}, 1, 0
    if str == nil then return out end
    while true do
        if max and n >= max - 1 then
            out[#out + 1] = sub(str, pos)
            return out
        end
        local s, e = find(str, sep, pos)
        if not s then
            out[#out + 1] = sub(str, pos)
            return out
        end
        if e < pos then e = pos end
        out[#out + 1] = sub(str, pos, s - 1)
        pos = e + 1
        n = n + 1
        if pos > #str then
            out[#out + 1] = ""
            return out
        end
    end
end

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
                if match(data, alpn) then
                    supported[alpn] = true
                end
            end
            local sel = match(data, "alpn[^%w]*(%S+)") or match(data, "selected[%s_]+protocol[%s:=]+([%w%./-]+)")
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
