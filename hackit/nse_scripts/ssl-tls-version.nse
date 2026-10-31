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
local msleep = function(ms)
    if stdnse and stdnse.sleep then
        return stdnse.sleep((ms or 0) / 1000)
    end
    if nmap.msleep then
        return nmap.msleep(ms or 0)
    end
    local deadline = nmap.clock() + (ms or 0) / 1000
    while nmap.clock() < deadline do end
    return true
end
local new_socket = nmap.new_socket
local resolve = nmap.resolve

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    if stdnse and stdnse.sleep then
        return stdnse.sleep(seconds)
    end
    if nmap.msleep then
        return nmap.msleep(math.max(0, math.floor((seconds or 0) * 1000)))
    end
    local deadline = nmap.clock() + (seconds or 0)
    while nmap.clock() < deadline do end
    return true
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
            local ver = match(d, "version[%s:=]+([%d%.]+)") or match(d, "(%u+)%-(%d%.?%d*)") or match(d, "([%d%.]+)[%s]*-[%s]*server")
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
