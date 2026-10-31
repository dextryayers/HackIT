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
    local socket = new_socket()
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
            return gsub(b, "[\r\n]+", " | "):sub(1, 300)
        end
        return nil
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return banner
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local out = output_table()
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
        if expected and find(banner, expected:match("%S+"), 1, true) then
            out.banner_matches_expected = true
        end
    else
        out.status = "NO_BANNER"
        out.message = "No banner received on port " .. port.number
    end
    return out
end
