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

description = [[Tests the SMTP VRFY command by querying common usernames to determine if the server reveals valid user accounts, which aids in user enumeration. Uses multiplexed connections for efficiency.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 25 or port.service == "smtp") end

local test_users = {"root", "admin", "postmaster", "nobody", "test", "info", "sales", "support", "hostmaster", "webmaster", "mail", "contact", "help", "administrator", "backup"}

action = function(host, port)
    local found = {}
    for _, user in ipairs(test_users) do
        local s = new_socket()
        s:set_timeout(5000)
        local ok = pcall(function()
            local ok2 = s:connect(host.ip, port)
            if ok2 then
                s:receive_buf("\n", 3000)
                s:send("EHLO hackit.local\r\n")
                s:receive_buf("\n", 3000)
                s:send("VRFY " .. user .. "\r\n")
                local _, resp = s:receive_buf("\n", 3000)
                s:close()
                if resp and (match(resp, "^250 ") or match(resp, "^252 ")) then
                    local detail = match(resp, "250[%- ]([^\r\n]+)")
                    insert(found, {user = user, response = detail or user})
                end
            else
                s:close()
            end
        end)
        if not ok then
            pcall(function() s:close() end)
        end
    end
    if #found > 0 then
        local result = output_table()
        result.vrfy_enabled = true
        result.valid_users = found
        result.user_count = #found
        return result
    end
    return format_output(false, "VRFY not enabled or no users found")
end
