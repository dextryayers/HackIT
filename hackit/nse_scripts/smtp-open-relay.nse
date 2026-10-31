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
