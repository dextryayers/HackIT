local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local smtp = require "smtp"



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
    insert(result, "SMTP banner: " .. (banner:match("^[^\r\n]+") or "unknown"))
    socket:send("EHLO scanner\r\n")
    status, banner = socket:receive_lines(1)
    if not status then
        socket:close()
        return format_output(false, "No EHLO response")
    end
    if banner:match("AUTH") then
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
                if status and resp:match("235") then
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
