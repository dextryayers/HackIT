local stdnse = require "stdnse"
local nmap = require "nmap"
local shortport = require "shortport"



-- nmp function cache
local nmap_register = nmap.register_script
local nmap_settitle = nmap.set_title
local nmap_resolve = nmap.resolve
local nmap_get_port_state = nmap.get_port_state
local nmap_set_port_state = nmap.set_port_state
local comm = nmap.comm
local new_socket = nmap.new_socket
local get_timeout = nmap.get_timeout

-- Performance optimizations
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
local move = table.move or function(a1, f, e, t, a2)
    if not a2 then a2 = a1 end
    for i = f, e do a2[t + i - f] = a1[i] end
    return a2
end
local tostring = tostring
local tonumber = tonumber
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local unpack = unpack or table.unpack
local setmetatable = setmetatable
local getmetatable = getmetatable
local error = error
local select = select
local clock = nmap.clock
local msleep = nmap.msleep
local sleep = stdnse.sleep
local strsplit = stdnse.strsplit
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
        if resp:match("%$") then
            local len = resp:match("%$(%d+)")
            if len then
                local _, data = sock:receive_buf("\r\n", 5000)
                sock:close()
                if data then
                    local current_section = "general"
                    for line in data:gmatch("([^\r\n]+)") do
                        local section = line:match("^# (.+)$")
                        if section then
                            current_section = section:lower():gsub("%s+", "_")
                            res[current_section] = res[current_section] or {}
                        else
                            local key, val = line:match("^([^:]+):(.+)$")
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
