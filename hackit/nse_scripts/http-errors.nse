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

description = [[Analyzes error pages for information disclosure by requesting non-existent paths and capturing error details.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local test_paths = {
        "/nonexistent12345.html",
        "/test.asp",
        "/test.aspx",
        "/test.php",
        "/test.jsp",
        "/test.cfm",
    }
    local results = {}
    for _, path in ipairs(test_paths) do
        local resp = http.get(host, port, path)
        if resp and resp.body and resp.body ~= "" then
            local info = {}
            if resp.find(body, "stack trace", 1, true) or resp.find(body, "Stack Trace", 1, true) then
                insert(info, "Stack trace")
            end
            if resp.find(body, "Warning:", 1, true) or resp.find(body, "Fatal error", 1, true) then
                insert(info, "PHP error")
            end
            if resp.find(body, "Exception", 1, true) then
                insert(info, "Exception details")
            end
            if resp.find(body, "Server Error", 1, true) then
                insert(info, "ASP.NET error")
            end
            if resp.find(body, "root:", 1, true) or resp.find(body, "jetty", 1, true) then
                insert(info, "Java stack trace")
            end
            if resp.find(body, "File not found", 1, true) or resp.find(body, "No such file", 1, true) then
                insert(info, "Path disclosure")
            end
            local path_info = resp.match(body, "in (%S+%.php)")
            if path_info then
                insert(info, "Path disclosed: " .. path_info)
            end
            if #info > 0 then
                insert(results, "Error at " .. path .. " [" .. concat(info, ", ") .. "]")
            end
        end
    end
    if #results == 0 then
        return format_output(false, "No information disclosure in error pages")
    end
    return format_output(true, concat(results, "\n"))
end
