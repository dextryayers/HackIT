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
local new_socket = nmap.new_socket
local resolve = nmap.resolve

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
