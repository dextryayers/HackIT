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

description = [[Checks HSTS (Strict-Transport-Security) header for max-age, includeSubDomains, and preload directives.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local response = http.get(host, port, "/")
    if not response or not response.header then
        return format_output(false, "No response")
    end
    local hsts = response.header["strict-transport-security"]
    if not hsts then
        return format_output(false, "HSTS header not found")
    end
    local results = {}
    insert(results, "HSTS: " .. hsts)
    local max_age = match(hsts, "max%-age=(%d+)")
    if max_age then
        local ma = tonumber(max_age)
        if ma then
            insert(results, "max-age: " .. ma .. " seconds (" .. math.floor(ma / 86400) .. " days)")
            if ma < 10886400 then
                insert(results, "WARNING: max-age less than recommended (126 days)")
            end
        end
    else
        insert(results, "WARNING: No max-age directive")
    end
    if find(hsts, "includeSubDomains") then
        insert(results, "includeSubDomains: YES")
    else
        insert(results, "includeSubDomains: NO (subdomains not covered)")
    end
    if find(hsts, "preload") then
        insert(results, "preload: YES (eligible for browser preload lists)")
    end
    return format_output(true, concat(results, "\n"))
end
