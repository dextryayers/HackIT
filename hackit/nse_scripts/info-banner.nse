local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Generic banner grab for any open TCP port.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local banner_greets = {
    [21]   = "FTP server",
    [22]   = "SSH server",
    [23]   = "Telnet server",
    [25]   = "SMTP server",
    [53]   = "DNS server",
    [80]   = "HTTP server",
    [110]  = "POP3 server",
    [143]  = "IMAP server",
    [443]  = "HTTPS server",
    [389]  = "LDAP server",
    [993]  = "IMAPS server",
    [995]  = "POP3S server",
    [1433] = "MSSQL server",
    [1521] = "Oracle DB",
    [3306] = "MySQL server",
    [5432] = "PostgreSQL server",
    [6379] = "Redis server",
    [8080] = "HTTP-Alt server",
    [8443] = "HTTPS-Alt server",
    [27017]= "MongoDB server",
}

local function send_greeting(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    local ok, banner = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local b = socket:receive_bytes(512)
        if port.number == 80 or port.number == 443 or port.number == 8080 or port.number == 8443 then
            socket:send("GET / HTTP/1.0\r\nHost: " .. host.ip .. "\r\n\r\n")
            b = socket:receive_bytes(4096)
        end
        if port.number == 25 or port.number == 587 then
            socket:send("EHLO probe\r\n")
            b = socket:receive_bytes(512)
        end
        socket:close()
        if b then
            return b:gsub("[\r\n]+", " | "):sub(1, 300)
        end
        return nil
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return banner
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local out = stdnse.output_table()
    out.service = "Banner Grabbing"
    out.target = host.ip
    out.port = port.number
    local expected = banner_greets[port.number]
    if expected then out.expected_service = expected end
    local banner = send_greeting(host, port)
    if banner then
        out.banner = banner
        out.banner_length = #banner
        out.status = "BANNER_RECEIVED"
        if expected and banner:find(expected:match("%S+"), 1, true) then
            out.banner_matches_expected = true
        end
    else
        out.status = "NO_BANNER"
        out.message = "No banner received on port " .. port.number
    end
    return out
end
