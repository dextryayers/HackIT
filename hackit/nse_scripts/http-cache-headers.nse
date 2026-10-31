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

description = [[Analyzes Cache-Control, Pragma, Expires, and ETag headers to assess caching behavior and potential information leakage.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local paths = {"/", "/login", "/admin", "/dashboard", "/profile"}
    local results = {}
    for _, path in ipairs(paths) do
        local resp = http.get(host, port, path)
        if resp and resp.header then
            local h = resp.header
            local line = path
            local cache_control = h["cache-control"]
            local pragma = h["pragma"]
            local expires = h["expires"]
            local etag = h["etag"]
            local issues = {}
            if cache_control then
                line = line .. " CC:" .. cache_control
                if find(cache_control, "no%-store") then
                elseif find(cache_control, "private") then
                    insert(issues, "Private cache (may contain sensitive data)")
                elseif find(cache_control, "public") and (path == "/login" or path == "/admin") then
                    insert(issues, "Sensitive path publicly cacheable")
                end
                if not find(cache_control, "no%-store") and not find(cache_control, "no%-cache") and not find(cache_control, "private") then
                    if path ~= "/" then
                        insert(issues, "No cache restriction directive")
                    end
                end
            else
                insert(issues, "No Cache-Control header")
            end
            if expires then
                line = line .. " Expires:" .. expires
            end
            if pragma then
                line = line .. " Pragma:" .. pragma
            end
            if etag then
                line = line .. " ETag:" .. etag
            end
            if #issues > 0 then
                line = line .. " [" .. concat(issues, "; ") .. "]"
            end
            insert(results, line)
        end
    end
    if #results == 0 then
        return format_output(false, "No cache header data available")
    end
    return format_output(true, concat(results, "\n"))
end
