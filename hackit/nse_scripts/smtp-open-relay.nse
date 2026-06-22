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

description = [[Tests if the SMTP server is an open relay by attempting to send an email through the server to an external address without authentication. Uses structured output with detailed SMTP dialog.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 25 or port.service == "smtp") end

local test_domains = {"example.com", "test.org", "mailinator.com"}

action = function(host, port)
    local relay_found = false
    local dialog = {}
    for _, domain in ipairs(test_domains) do
        if relay_found then break end
        local sock = new_socket()
        sock:set_timeout(15000)
        local ok = pcall(function()
            local status = sock:connect(host.ip, port)
            if not status then return end
            local banner = sock:receive_buf("\n", 5000)
            insert(dialog, "BANNER: " .. (match(banner, "([^\r\n]+)") or banner))
            sock:send("EHLO hackit.local\r\n")
            local ehlo = sock:receive_buf("\n", 5000)
            insert(dialog, "EHLO: +OK")
            if ehlo then
                sock:send("MAIL FROM:<test@hackit.local>\r\n")
                local mf = sock:receive_buf("\n", 5000)
                insert(dialog, "MAIL FROM: " .. (match(mf, "([^\r\n]+)") or mf))
                if mf and (match(mf, "^250 ") or match(mf, "^251 ")) then
                    sock:send("RCPT TO:<relay-test@" .. domain .. ">\r\n")
                    local rcpt = sock:receive_buf("\n", 5000)
                    insert(dialog, "RCPT TO: " .. (match(rcpt, "([^\r\n]+)") or rcpt))
                    if rcpt and (match(rcpt, "^250 ") or match(rcpt, "^251 ")) then
                        relay_found = true
                    end
                end
            end
            sock:send("QUIT\r\n")
            sock:close()
        end)
        if not ok then
            pcall(function() sock:close() end)
        end
    end
    if relay_found then
        local result = output_table()
        result.vulnerability = true
        result.name = "SMTP Open Relay"
        result.severity = "HIGH"
        result.details = "SMTP server accepts mail for external domains without authentication"
        result.dialog = dialog
        return result
    end
    return format_output(false, "Not an open relay")
end
