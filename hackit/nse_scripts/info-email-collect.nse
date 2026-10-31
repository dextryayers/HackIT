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

description = [[Collects email addresses from SMTP VRFY, EXPN, and public HTTP pages.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local email_pattern = "([%w._%%%-]+@[%w._-]+%.[%a][%a]+)"
local common_accounts = {"postmaster", "admin", "info", "sales", "support", "contact", "nobody", "mail", "office", "manager", "help", "webmaster", "hostmaster", "abuse", "security", "spam", "billing", "hr", "jobs", "marketing", "press", "registrar"}
local common_domains = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "example.com"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local out = output_table()
    out.service = "Email Collector"
    out.target = host.ip
    out.port = port.number
    local emails = {}
    if port.number == 25 or port.number == 587 then
        local socket = new_socket()
        socket:set_timeout(10000)
        local ok = pcall(function()
            local status, err = socket:connect(host, port)
            if not status then return end
            socket:receive_bytes(128)
            socket:send("EHLO collector\r\n")
            local ehlo = socket:receive_bytes(512)
            local has_vrfy = ehlo and find(ehlo, "VRFY")
            local has_expn = ehlo and find(ehlo, "EXPN")
            if has_vrfy then
                for _, addr in ipairs(common_accounts) do
                    socket:send("VRFY " .. addr .. "\r\n")
                    local _, resp = socket:receive_bytes(128)
                    if resp and (find(resp, "250") or find(resp, "252") or find(resp, "2.1.5") or find(resp, "2.0.0")) then
                        insert(emails, {address = addr .. "@" .. (host.name or host.ip), method = "VRFY"})
                    end
                end
            end
            if has_expn then
                for _, addr in ipairs(common_accounts) do
                    socket:send("EXPN " .. addr .. "\r\n")
                    local _, resp = socket:receive_bytes(128)
                    if resp and (find(resp, "250") or find(resp, "252")) then
                        local expanded = match(resp, "<([^>]+)>")
                        if expanded then
                            insert(emails, {address = expanded, method = "EXPN"})
                        end
                    end
                end
            end
            for _, addr in ipairs(common_accounts) do
                socket:send("MAIL FROM:<probe@test.com>\r\n")
                socket:receive_bytes(128)
                socket:send("RCPT TO:<" .. addr .. "@" .. (host.name or "test.local") .. ">\r\n")
                local _, resp = socket:receive_bytes(128)
                if resp and (find(resp, "250") or find(resp, "2.1.5")) then
                    insert(emails, {address = addr .. "@" .. (host.name or host.ip), method = "RCPT TO"})
                end
                socket:send("RSET\r\n")
                socket:receive_bytes(128)
            end
            socket:send("QUIT\r\n")
            socket:close()
        end)
        if not ok then pcall(socket.close, socket) end
    end
    if port.number == 80 or port.number == 8080 or port.number == 443 then
        local paths = {"/", "/contact", "/about", "/team", "/support", "/help", "/index.html", "/about.php", "/contact.php"}
        for _, path in ipairs(paths) do
            local socket = new_socket()
            socket:set_timeout(5000)
            local ok = pcall(function()
                local status, err = socket:connect(host, port)
                if not status then return end
                socket:send("GET " .. path .. " HTTP/1.1\r\nHost: " .. host.ip .. "\r\nConnection: close\r\n\r\n")
                local _, resp = socket:receive_bytes(8192)
                socket:close()
                if resp then
                    for match in gmatch(resp, email_pattern) do
                        local already = false
                        for _, e in ipairs(emails) do
                            if e.address == match then already = true end
                        end
                        if not already then
                            insert(emails, {address = match, method = "HTTP:" .. path})
                        end
                    end
                end
            end)
            if not ok then pcall(socket.close, socket) end
        end
    end
    if #emails > 0 then
        local unique = {}
        local seen = {}
        for _, e in ipairs(emails) do
            if not seen[e.address] then
                seen[e.address] = true
                insert(unique, e)
            end
        end
        out.status = "EMAILS_COLLECTED"
        out.emails = unique
        out.email_count = #unique
    else
        out.status = "NONE_FOUND"
        out.message = "No email addresses collected"
    end
    return out
end
