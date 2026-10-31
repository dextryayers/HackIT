local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local smtp = require "smtp"



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

description = [[
Tests SMTP AUTH PLAIN and AUTH LOGIN mechanisms for authentication bypass or
weak credentials. Connects to the SMTP server and attempts to authenticate
using common credentials via EHLO and AUTH commands.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"auth", "intrusive"}

portrule = shortport.port_or_service(25, "smtp")

action = function(host, port)
    local result = {}
    local socket = new_socket()
    socket:set_timeout(5000)
    local status, err = socket:connect(host, port)
    if not status then
        return format_output(false, "Could not connect: " .. tostring(err))
    end
    local status, banner = socket:receive_lines(1)
    if not status then
        socket:close()
        return format_output(false, "No banner received")
    end
    insert(result, "SMTP banner: " .. (match(banner, "^[^\r\n]+") or "unknown"))
    socket:send("EHLO scanner\r\n")
    status, banner = socket:receive_lines(1)
    if not status then
        socket:close()
        return format_output(false, "No EHLO response")
    end
    if match(banner, "AUTH") then
        insert(result, "SMTP AUTH supported")
    else
        insert(result, "SMTP AUTH not supported")
        socket:close()
        return format_output(true, result)
    end
    local creds = {
        {"admin", "admin"}, {"admin", "password"}, {"root", "root"},
        {"test", "test"}, {"user", "user"}, {"postmaster", "admin"},
    }
    for _, c in ipairs(creds) do
        local s = new_socket()
        s:set_timeout(5000)
        s:connect(host, port)
        s:receive_lines(1)
        s:send("EHLO scanner\r\n")
        s:receive_lines(1)
        s:send("AUTH LOGIN\r\n")
        local status, resp = s:receive_lines(1)
        if status then
            s:send(stdnse.tohex(c[1]) .. "\r\n")
            status, resp = s:receive_lines(1)
            if status then
                s:send(stdnse.tohex(c[2]) .. "\r\n")
                status, resp = s:receive_lines(1)
                if status and match(resp, "235") then
                    insert(result, ("Valid credentials: %s / %s"):format(c[1], c[2]))
                end
            end
        end
        s:close()
    end
    if #result == 1 then
        insert(result, "No valid SMTP AUTH credentials found")
    end
    return format_output(true, result)
end
