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
local msleep = function(ms)
    if stdnse and stdnse.sleep then
        return stdnse.sleep((ms or 0) / 1000)
    end
    if nmap.msleep then
        return nmap.msleep(ms or 0)
    end
    local deadline = nmap.clock() + (ms or 0) / 1000
    while nmap.clock() < deadline do end
    return true
end
local new_socket = nmap.new_socket
local resolve = nmap.resolve

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    if stdnse and stdnse.sleep then
        return stdnse.sleep(seconds)
    end
    if nmap.msleep then
        return nmap.msleep(math.max(0, math.floor((seconds or 0) * 1000)))
    end
    local deadline = nmap.clock() + (seconds or 0)
    while nmap.clock() < deadline do end
    return true
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
