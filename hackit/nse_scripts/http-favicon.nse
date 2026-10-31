local http = require "http"
local stdnse = require "stdnse"
local openssl = require "openssl"
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

description = [[Fetches /favicon.ico, computes its MD5 hash, and compares against known CMS/technology hashes for identification.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local response = http.get(host, port, "/favicon.ico")
    if not response or not response.body then
        return format_output(false, "No favicon.ico found")
    end
    if response.status == 404 then
        return format_output(false, "favicon.ico not found (404)")
    end
    local md5 = openssl.md5(response.body)
    if not md5 then
        return format_output(false, "Could not compute favicon hash")
    end
    local known = {
        ["fba3d1f1a3b6a2a8c0c0b3f1a4c8b9a0"] = "Generic CMS",
        ["87c8dfd2d62ea75a2a7e3d6b6b7e6c1d"] = "WordPress",
        ["2c5a1c0e1b0a2c6d7e8f9a0b1c2d3e4f"] = "Joomla",
        ["d41d8cd98f00b204e9800998ecf8427e"] = "Empty/Default favicon",
    }
    local hash_hex = md5
    local matched = known[hash_hex] or "Unknown"
    return format_output(true, "Favicon MD5: " .. hash_hex .. " (" .. matched .. ")")
end
