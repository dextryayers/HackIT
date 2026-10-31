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
    if data and (match(data, method) or match(data, "compression")) then
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
