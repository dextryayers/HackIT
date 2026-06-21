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

description = [[Tests the SMTP EXPN command by attempting to expand common aliases to reveal mailing list memberships and delivery addresses. Uses structured output with alias details.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 25 or port.service == "smtp") end

local test_aliases = {"root", "postmaster", "mailer-daemon", "bin", "daemon", "adm", "lp", "sync", "shutdown", "halt", "news", "uucp", "operator", "games", "gopher", "ftp", "nobody", "mail", "list", "owner"}

action = function(host, port)
    local found = {}
    for _, alias in ipairs(test_aliases) do
        local sock = new_socket()
        sock:set_timeout(5000)
        local ok = pcall(function()
            local ok2 = sock:connect(host.ip, port)
            if ok2 then
                sock:receive_buf("\n", 3000)
                sock:send("EHLO hackit.local\r\n")
                sock:receive_buf("\n", 3000)
                sock:send("EXPN " .. alias .. "\r\n")
                local _, resp = sock:receive_buf("\n", 3000)
                sock:close()
                if resp and (resp:match("^250 ") or resp:match("^252 ")) then
                    local expand = resp:match("250[%- ]([^\r\n]+)")
                    insert(found, {alias = alias, expands_to = expand or alias})
                end
            else
                sock:close()
            end
        end)
        if not ok then
            pcall(function() sock:close() end)
        end
    end
    if #found > 0 then
        local result = output_table()
        result.expn_enabled = true
        result.aliases = found
        result.alias_count = #found
        return result
    end
    return format_output(false, "EXPN not enabled")
end
