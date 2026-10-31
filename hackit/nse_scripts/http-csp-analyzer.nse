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

description = [[Analyzes Content-Security-Policy header directives for misconfigurations and missing protections.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local response = http.get(host, port, "/")
    if not response or not response.header then
        return format_output(false, "No response")
    end
    local csp = response.header["content-security-policy"]
    if not csp then
        return format_output(false, "CSP header not found")
    end
    local results = {}
    insert(results, "CSP: " .. sub(csp, 1, 200))
    if find(csp, "unsafe%-inline") then
        insert(results, "WARNING: 'unsafe-inline' detected (XSS risk)")
    end
    if find(csp, "unsafe%-eval") then
        insert(results, "WARNING: 'unsafe-eval' detected")
    end
    if find(csp, "%*%s") or find(csp, ":%s*%*") then
        insert(results, "WARNING: Wildcard (*) source detected in directives")
    end
    if find(csp, "http://") then
        insert(results, "WARNING: HTTP protocol allowed in CSP")
    end
    if not find(csp, "default%-src") then
        insert(results, "NOTE: No default-src directive (falls back to no restriction)")
    end
    if not find(csp, "script%-src") then
        insert(results, "NOTE: No script-src directive")
    end
    local directives = {}
    for d in gmatch(csp, "([^;]+)") do
        insert(directives, match(d, "^%s*(.-)%s*$"))
    end
    insert(results, "Directives found: " .. #directives)
    return format_output(true, concat(results, "\n"))
end
