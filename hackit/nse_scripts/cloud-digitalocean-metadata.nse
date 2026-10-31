local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local http = require "http"



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

description = [[
Checks for the DigitalOcean metadata service at 169.254.169.254. Attempts to
access the DigitalOcean-specific metadata endpoint to retrieve droplet
information such as hostname, region, and user-data.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(80, "http")

action = function(host, port)
    local result = {}
    local meta_host = "169.254.169.254"
    local meta_socket = new_socket()
    meta_socket:set_timeout(3000)
    local status, err = meta_socket:connect(meta_host, 80)
    if not status then
        return format_output(false, "Metadata service not accessible: " .. tostring(err))
    end
    local paths = {
        "/metadata/v1/id",
        "/metadata/v1/hostname",
        "/metadata/v1/region",
        "/metadata/v1/user-data",
        "/metadata/v1/private-networks",
        "/metadata/v1/public-keys",
        "/metadata/v1/interfaces/private/0/ipv4/address",
        "/metadata/v1/interfaces/public/0/ipv4/address",
    }
    for _, path in ipairs(paths) do
        meta_socket:send("GET " .. path .. " HTTP/1.1\r\nHost: metadata\r\nConnection: close\r\n\r\n")
        local status, response = meta_socket:receive_bytes(1)
        if status and response then
            local body = match(response, "\r\n\r\n(.*)")
            if body and #body > 0 and not match(body, "404") and not match(body, "Not Found") then
                insert(result, ("DigitalOcean metadata: %s = %s"):format(path, (gsub(body, "%s+", " "):sub(1, 100))))
            end
        end
    end
    meta_socket:close()
    if #result == 0 then
        insert(result, "DigitalOcean metadata service not available")
    end
    return format_output(true, result)
end
