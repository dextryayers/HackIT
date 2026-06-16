local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Enumerates valid usernames via SMTP VRFY, EXPN, or RCPT TO.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "audit"}

local common_users = {"admin", "root", "test", "user", "info", "support", "postmaster", "sales", "contact", "nobody", "mail", "office", "manager", "help", "service", "webmaster", "hostmaster", "abuse", "security", "spam"}

local functions = {"VRFY", "EXPN", "RCPT TO:<%s@local.domain>"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 25 or port.number == 587) end

action = function(host, port)
    local out = stdnse.output_table()
    out.service = "SMTP User Enumeration"
    out.target = host.ip
    out.port = port.number
    local enumerated = {}
    local supported_cmds = {}

    for _, func in ipairs(functions) do
        local socket = nmap.new_socket()
        socket:set_timeout(10000)
        local ok, banner = pcall(function()
            local status, err = socket:connect(host, port)
            if not status then return nil end
            local b = socket:receive_bytes(128)
            socket:send("EHLO hackit\r\n")
            local ehlo = socket:receive_bytes(512)
            socket:close()
            if ehlo then
                if ehlo:find(func) then
                    supported_cmds[#supported_cmds + 1] = func
                end
            end
            return b
        end)
        if not ok then pcall(socket.close, socket) end
    end

    if #supported_cmds == 0 then
        table.insert(supported_cmds, "VRFY")
    end

    for _, func in ipairs(supported_cmds) do
        local socket = nmap.new_socket()
        socket:set_timeout(10000)
        local ok = pcall(function()
            local status, err = socket:connect(host, port)
            if not status then return end
            socket:receive_bytes(128)
            socket:send("EHLO hackit\r\n")
            socket:receive_bytes(512)
            for _, u in ipairs(common_users) do
                local query = func
                if func:find("RCPT TO") then
                    query = "RCPT TO:<" .. u .. "@test.local>"
                else
                    query = func .. " " .. u
                end
                socket:send(query .. "\r\n")
                local _, resp = socket:receive_bytes(128)
                if resp and (resp:find("252") or resp:find("250") or resp:find("2.1.5")) then
                    enumerated[#enumerated + 1] = {user = u, method = func:gsub("%%.*", "")}
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
