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

description = [[Checks for Microsoft FrontPage Server Extensions by probing common FPSE paths and RPC endpoints.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local fpse_paths = {
        "/_vti_inf.html",
        "/_vti_pvt/",
        "/_vti_bin/shtml.dll",
        "/_vti_bin/_vti_aut/author.dll",
        "/_vti_bin/fpcount.exe",
        "/cgi-bin/shtml.dll",
    }
    local results = {}
    for _, path in ipairs(fpse_paths) do
        local resp = http.get(host, port, path)
        if resp and resp.status and resp.status < 400 then
            if resp.body and resp.find(body, "FrontPage") or resp.find(body, "VERSION") then
                insert(results, "FPSE detected at " .. path)
            elseif resp.status ~= 404 then
                insert(results, "Possible FPSE at " .. path .. " (status " .. resp.status .. ")")
            end
        end
    end
    if #results == 0 then
        return format_output(false, "No FrontPage extensions detected")
    end
    return format_output(true, concat(results, "\n"))
end
