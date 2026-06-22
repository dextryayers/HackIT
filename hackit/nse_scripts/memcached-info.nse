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
