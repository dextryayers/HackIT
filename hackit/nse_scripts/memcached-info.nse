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

description = [[Connects to a Memcached server and issues the "stats" command to retrieve server statistics and configuration parameters. Uses structured output with version extraction.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 11211 or port.service == "memcache") end

local commands = {"stats\r\n", "stats settings\r\n", "stats items\r\n", "version\r\n"}

action = function(host, port)
    local sock = new_socket()
    sock:set_timeout(10000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return end
        local result = output_table()
        for _, cmd in ipairs(commands) do
            sock:send(cmd)
            local _, resp = sock:receive_buf("\r\n", 5000)
            if resp then
                for line in gmatch(resp, "([^\r\n]+)") do
                    if cmd == "version\r\n" then
                        local ver = match(line, "VERSION ([^\r\n]+)")
                        if ver then result.version = ver end
                    else
                        local parts = {}
                        for part in gmatch(line, "%S+") do
                            insert(parts, part)
                        end
                        if parts[1] == "STAT" and #parts >= 3 then
                            local key = parts[2]
                            local val = parts[3]
                            for i = 4, #parts do
                                val = val .. " " .. parts[i]
                            end
                            if not result[key] then
                                result[key] = val
                            end
                        end
                    end
                end
            end
        end
        sock:close()
        if next(result) then return result end
    end)
    if not ok then
        pcall(function() sock:close() end)
    end
    if not result or not next(result) then
        return format_output(false, "Could not parse Memcached stats")
    end
    return result
end
