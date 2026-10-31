local http = require "http"
local stdnse = require "stdnse"
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

description = [[Tests which HTTP methods are allowed on the target by sending OPTIONS requests and probing common methods individually.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local options_resp = http.generic_request(host, port, "OPTIONS", "/")
    local allowed = {}
    if options_resp and options_resp.header and options_resp.header["allow"] then
        for m in options_resp.header["allow"]:gmatch("%S+") do
            insert(allowed, m)
        end
    end
    local methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
    local results = {}
    for _, method in ipairs(methods) do
        local resp = http.generic_request(host, port, method, "/")
        if resp and resp.status then
            local status_code = resp.status
            if status_code ~= 405 and status_code ~= 501 and status_code ~= 400 then
                insert(results, method .. " (" .. status_code .. ")")
            end
        end
    end
    if #results == 0 then
        return format_output(false, "No non-standard methods detected")
    end
    if #allowed > 0 then
        insert(results, "OPTIONS Allow: " .. concat(allowed, ", "))
    end
    return format_output(true, "Allowed methods: " .. concat(results, ", "))
end
