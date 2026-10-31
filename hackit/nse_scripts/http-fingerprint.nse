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

description = [[Fingerprints the web server by analyzing Server header, response patterns, X-Powered-By, and cookie naming conventions.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local resp = http.get(host, port, "/")
    if not resp or not resp.header then
        return format_output(false, "No response")
    end
    local h = resp.header
    local sigs = {}
    if h["server"] then
        insert(sigs, "Server: " .. h["server"])
    end
    if h["x-powered-by"] then
        insert(sigs, "X-Powered-By: " .. h["x-powered-by"])
    end
    if h["x-aspnet-version"] then
        insert(sigs, "ASP.NET: " .. h["x-aspnet-version"])
    end
    if h["x-generator"] then
        insert(sigs, "Generator: " .. h["x-generator"])
    end
    if h["via"] then
        insert(sigs, "Via: " .. h["via"])
    end
    if resp.body then
        if find(resp.body or "", "wp%-content") or find(resp.body or "", "wp%-includes") then
            insert(sigs, "CMS: WordPress")
        end
        if find(resp.body or "", "Joomla") then
            insert(sigs, "CMS: Joomla")
        end
        if find(resp.body or "", "Drupal") then
            insert(sigs, "CMS: Drupal")
        end
        if find(resp.body or "", "nginx") then
            insert(sigs, "Server: nginx (body hint)")
        end
    end
    if #sigs == 0 then
        return format_output(false, "No fingerprinting signatures found")
    end
    return format_output(true, concat(sigs, "\n"))
end
