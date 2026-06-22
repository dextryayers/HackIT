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

description = [[Enumerates valid usernames via SMTP VRFY, EXPN, or RCPT TO.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "audit"}

local common_users = {"admin", "root", "test", "user", "info", "support", "postmaster", "sales", "contact", "nobody", "mail", "office", "manager", "help", "service", "webmaster", "hostmaster", "abuse", "security", "spam"}

local functions = {"VRFY", "EXPN", "RCPT TO:<%s@local.domain>"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 25 or port.number == 587) end

action = function(host, port)
    local out = output_table()
    out.service = "SMTP User Enumeration"
    out.target = host.ip
    out.port = port.number
    local enumerated = {}
    local supported_cmds = {}

    for _, func in ipairs(functions) do
        local socket = new_socket()
        socket:set_timeout(10000)
        local ok, banner = pcall(function()
            local status, err = socket:connect(host, port)
            if not status then return nil end
            local b = socket:receive_bytes(128)
            socket:send("EHLO hackit\r\n")
            local ehlo = socket:receive_bytes(512)
            socket:close()
            if ehlo then
                if find(ehlo, func) then
                    insert(supported_cmds, func)
                end
            end
            return b
        end)
        if not ok then pcall(socket.close, socket) end
    end

    if #supported_cmds == 0 then
        insert(supported_cmds, "VRFY")
    end

    for _, func in ipairs(supported_cmds) do
        local socket = new_socket()
        socket:set_timeout(10000)
        local ok = pcall(function()
            local status, err = socket:connect(host, port)
            if not status then return end
            socket:receive_bytes(128)
            socket:send("EHLO hackit\r\n")
            socket:receive_bytes(512)
            for _, u in ipairs(common_users) do
                local query = func
                if find(func, "RCPT TO") then
                    query = "RCPT TO:<" .. u .. "@test.local>"
                else
                    query = func .. " " .. u
                end
                socket:send(query .. "\r\n")
                local _, resp = socket:receive_bytes(128)
                if resp and (find(resp, "252") or find(resp, "250") or find(resp, "2.1.5")) then
                    insert(enumerated, {user = u, method = gsub(func, "%%.*", "")})
                end
            end
            socket:send("QUIT\r\n")
            socket:close()
        end)
        if not ok then pcall(socket.close, socket) end
    end

    out.commands_supported = supported_cmds
    if #enumerated > 0 then
        out.status = "USERS_FOUND"
        out.valid_users = enumerated
        out.user_count = #enumerated
    else
        out.status = "NO_USERS"
        out.message = "No users enumerated via SMTP commands"
    end
    return out
end
