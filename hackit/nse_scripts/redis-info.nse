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

description = [[Connects to a Redis server and issues the INFO command to retrieve configuration, statistics, and server information. Uses structured output with version extraction and categorized sections.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 6379 or port.service == "redis") end

action = function(host, port)
    local sock = new_socket()
    sock:set_timeout(10000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return end
        sock:send("*1\r\n$4\r\nINFO\r\n")
        local _, resp = sock:receive_buf("\r\n", 5000)
        if not resp then sock:close(); return end
        local res = output_table()
        if match(resp, "%$") then
            local len = match(resp, "%$(%d+)")
            if len then
                local _, data = sock:receive_buf("\r\n", 5000)
                sock:close()
                if data then
                    local current_section = "general"
                    for line in gmatch(data, "([^\r\n]+)") do
                        local section = match(line, "^# (.+)$")
                        if section then
                            current_section = lower(section):gsub("%s+", "_")
                            res[current_section] = res[current_section] or {}
                        else
                            local key, val = match(line, "^([^:]+):(.+)$")
                            if key and val then
                                if current_section == "general" then
                                    res[key] = val
                                else
                                    if not res[current_section] then
                                        res[current_section] = {}
                                    end
                                    res[current_section][key] = val
                                end
                                if key == "redis_version" then
                                    res.version = val
                                end
                            end
                        end
                    end
                end
            else
                sock:close()
            end
        else
            sock:close()
        end
        if next(res) then return res end
    end)
    if not ok then
        pcall(function() sock:close() end)
    end
    if not result or not next(result) then
        return format_output(false, "Could not retrieve Redis info")
    end
    return result
end
