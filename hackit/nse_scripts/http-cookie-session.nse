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

description = [[Analyzes session cookies for randomness, length, and security attributes.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local resp = http.get(host, port, "/")
    if not resp or not resp.header then
        return format_output(false, "No response")
    end
    local cookies = resp.header["set-cookie"]
    if not cookies then
        return format_output(false, "No session cookies set")
    end
    if type(cookies) == "string" then
        cookies = {cookies}
    end
    local results = {}
    for _, cookie in ipairs(cookies) do
        local name = match(cookie, "^([^=]+)")
        local value = match(cookie, "^[^=]+=([^;]+)")
        local analysis = {}
        if name then
            if find(name, "[Ss]ession") or find(name, "PHPSESSID") or find(name, "JSESSIONID") or find(name, "ASP%.NET") or find(name, "laravel") then
                insert(analysis, "Session cookie detected")
            end
        end
        if value then
            insert(analysis, "Length: " .. #value .. " chars")
            local entropy = 0
            for c in gmatch(value, ".") do
                if find(c, "[a-z]") then entropy = entropy + 1 end
                if find(c, "[A-Z]") then entropy = entropy + 1 end
                if find(c, "[0-9]") then entropy = entropy + 2 end
            end
            if entropy < #value * 0.5 then
                insert(analysis, "Low entropy (possible predictability)")
            end
            if match(value, "^%d+$") then
                insert(analysis, "WARNING: Numeric only (predictable)")
            end
        end
        if find(cookie, "HttpOnly") then
            insert(analysis, "HttpOnly: Yes")
        else
            insert(analysis, "HttpOnly: No")
        end
        if find(cookie, "Secure") then
            insert(analysis, "Secure: Yes")
        else
            insert(analysis, "Secure: No")
        end
        local max_age = match(cookie, "Max%-Age=(%d+)")
        if max_age then
            insert(analysis, "Max-Age: " .. max_age .. "s")
        end
        insert(results, name .. ": " .. concat(analysis, ", "))
    end
    return format_output(true, concat(results, "\n"))
end
