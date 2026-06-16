local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Collects email addresses from SMTP VRFY, EXPN, and public HTTP pages.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local email_pattern = "([%w._%%%-]+@[%w._-]+%.[%a][%a]+)"
local common_accounts = {"postmaster", "admin", "info", "sales", "support", "contact", "nobody", "mail", "office", "manager", "help", "webmaster", "hostmaster", "abuse", "security", "spam", "billing", "hr", "jobs", "marketing", "press", "registrar"}
local common_domains = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "example.com"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local out = stdnse.output_table()
    out.service = "Email Collector"
    out.target = host.ip
    out.port = port.number
    local emails = {}
    if port.number == 25 or port.number == 587 then
        local socket = nmap.new_socket()
        socket:set_timeout(10000)
        local ok = pcall(function()
            local status, err = socket:connect(host, port)
            if not status then return end
            socket:receive_bytes(128)
            socket:send("EHLO collector\r\n")
            local ehlo = socket:receive_bytes(512)
            local has_vrfy = ehlo and ehlo:find("VRFY")
            local has_expn = ehlo and ehlo:find("EXPN")
            if has_vrfy then
                for _, addr in ipairs(common_accounts) do
                    socket:send("VRFY " .. addr .. "\r\n")
                    local _, resp = socket:receive_bytes(128)
                    if resp and (resp:find("250") or resp:find("252") or resp:find("2.1.5") or resp:find("2.0.0")) then
                        emails[#emails + 1] = {address = addr .. "@" .. (host.name or host.ip), method = "VRFY"}
                    end
                end
            end
            if has_expn then
                for _, addr in ipairs(common_accounts) do
                    socket:send("EXPN " .. addr .. "\r\n")
                    local _, resp = socket:receive_bytes(128)
                    if resp and (resp:find("250") or resp:find("252")) then
                        local expanded = resp:match("<([^>]+)>")
                        if expanded then
                            emails[#emails + 1] = {address = expanded, method = "EXPN"}
                        end
                    end
                end
            end
            for _, addr in ipairs(common_accounts) do
                socket:send("MAIL FROM:<probe@test.com>\r\n")
                socket:receive_bytes(128)
                socket:send("RCPT TO:<" .. addr .. "@" .. (host.name or "test.local") .. ">\r\n")
                local _, resp = socket:receive_bytes(128)
                if resp and (resp:find("250") or resp:find("2.1.5")) then
                    emails[#emails + 1] = {address = addr .. "@" .. (host.name or host.ip), method = "RCPT TO"}
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
            local socket = nmap.new_socket()
            socket:set_timeout(5000)
            local ok = pcall(function()
                local status, err = socket:connect(host, port)
                if not status then return end
                socket:send("GET " .. path .. " HTTP/1.1\r\nHost: " .. host.ip .. "\r\nConnection: close\r\n\r\n")
                local _, resp = socket:receive_bytes(8192)
                socket:close()
                if resp then
                    for match in resp:gmatch(email_pattern) do
                        local already = false
                        for _, e in ipairs(emails) do
                            if e.address == match then already = true end
                        end
                        if not already then
                            emails[#emails + 1] = {address = match, method = "HTTP:" .. path}
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
                unique[#unique + 1] = e
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
