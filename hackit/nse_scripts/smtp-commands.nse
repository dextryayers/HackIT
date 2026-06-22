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

description = [[Connects to the SMTP server and enumerates supported commands by sending the EHLO/HELO command and parsing the response for supported ESMTP extensions and commands. Uses structured output with version extraction.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 25 or port.service == "smtp") end

action = function(host, port)
    local sock = new_socket()
    sock:set_timeout(10000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return end
        local banner = sock:receive_buf("\n", 5000)
        if not banner then sock:close(); return end
        sock:send("EHLO hackit.local\r\n")
        local resp = sock:receive_buf("\n", 5000)
        local all_extensions = {}
        if resp then
            local lines = gmatch(resp, "250[%- ]([^\r\n]+)")
            for line in lines do
                insert(all_extensions, line)
            end
        end
        sock:send("HELO hackit.local\r\n")
        local helo_resp = sock:receive_buf("\n", 3000)
        sock:close()
        local res = output_table()
        res.banner = match(banner, "220[%s-]([^\r\n]+)") or match(banner, "220([^\r\n]+)")
        if #all_extensions > 0 then
            res.esmtp_extensions = all_extensions
        end
        local commands = {}
        for _, ext in ipairs(all_extensions) do
            local name = match(ext, "^(%w+)")
            if name then
                commands[name] = true
            end
        end
        res.command_summary = {}
        for k in pairs(commands) do
            insert(res.command_summary, k)
        end
        local ver = match(banner, "([%d%.]+)") or (resp and match(resp, "([%d%.]+)"))
        if ver then res.version = ver end
        return res
    end)
    if not ok then
        pcall(function() sock:close() end)
    end
    if not result then
        return format_output(false, "Could not enumerate SMTP commands")
    end
    return result
end
