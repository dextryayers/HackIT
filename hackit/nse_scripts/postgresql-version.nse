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

description = [[Connects to a PostgreSQL server and extracts version information from the server's startup banner and protocol negotiation. Uses structured output with version extraction and auth type detection.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 5432 or port.service == "postgresql") end

local startup_variants = {
    char(0x00, 0x00, 0x00, 0x5a, 0x00, 0x03, 0x00, 0x00, 0x75, 0x73, 0x65, 0x72, 0x00, 0x70, 0x6f, 0x73, 0x74, 0x67, 0x72, 0x65, 0x73, 0x00, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x00, 0x70, 0x6f, 0x73, 0x74, 0x67, 0x72, 0x65, 0x73, 0x00, 0x00),
    char(0x00, 0x00, 0x00, 0x4a, 0x00, 0x03, 0x00, 0x00, 0x75, 0x73, 0x65, 0x72, 0x00, 0x70, 0x6f, 0x73, 0x74, 0x67, 0x72, 0x65, 0x73, 0x00, 0x00),
}

action = function(host, port)
    for _, startup in ipairs(startup_variants) do
        local sock = new_socket()
        sock:set_timeout(10000)
        local ok, result = pcall(function()
            local status = sock:connect(host.ip, port)
            if not status then return end
            sock:send(startup)
            local _, resp = sock:receive_buf("", 5000)
            sock:close()
            if resp and #resp >= 5 then
                local res = output_table()
                local error_severity = match(resp, "([A-Z]+)")
                if error_severity and (error_severity == "FATAL" or error_severity == "ERROR") then
                    local msg = match(resp, "([^\x00]+)")
                    res.error = msg or "authentication error"
                    local v = match(resp, "version%s+([%d%.]+)") or match(resp, "PostgreSQL%s+([%d%.]+)")
                    if v then
                        res.version = v
                        local major = match(v, "^(%d+)")
                        if major then res.version_major = tonumber(major) end
                    end
                end
                local auth_type = byte(resp, 5)
                if auth_type == 0x00 then
                    res.authentication = "trust (no password required)"
                elseif auth_type == 0x03 then
                    res.authentication = "password required"
                elseif auth_type == 0x05 then
                    res.authentication = "md5 password required"
                elseif auth_type == 0x06 then
                    res.authentication = "SCAM credential exchange"
                else
                    res.authentication = "type " .. tostring(auth_type)
                end
                local v2 = match(resp, "server_version[^\x00]*([%d%.]+)")
                if v2 then
                    res.version = v2
                    local major = match(v2, "^(%d+)")
                    if major then res.version_major = tonumber(major) end
                end
                if next(res) then return res end
            end
        end)
        if not ok then
            pcall(function() sock:close() end)
        end
        if result and next(result) then
            return result
        end
    end
    return format_output(false, "Could not determine PostgreSQL version")
end
