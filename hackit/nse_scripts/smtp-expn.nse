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

description = [[Tests the SMTP EXPN command by attempting to expand common aliases to reveal mailing list memberships and delivery addresses. Uses structured output with alias details.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 25 or port.service == "smtp") end

local test_aliases = {"root", "postmaster", "mailer-daemon", "bin", "daemon", "adm", "lp", "sync", "shutdown", "halt", "news", "uucp", "operator", "games", "gopher", "ftp", "nobody", "mail", "list", "owner"}

action = function(host, port)
    local found = {}
    for _, alias in ipairs(test_aliases) do
        local sock = new_socket()
        sock:set_timeout(5000)
        local ok = pcall(function()
            local ok2 = sock:connect(host.ip, port)
            if ok2 then
                sock:receive_buf("\n", 3000)
                sock:send("EHLO hackit.local\r\n")
                sock:receive_buf("\n", 3000)
                sock:send("EXPN " .. alias .. "\r\n")
                local _, resp = sock:receive_buf("\n", 3000)
                sock:close()
                if resp and (match(resp, "^250 ") or match(resp, "^252 ")) then
                    local expand = match(resp, "250[%- ]([^\r\n]+)")
                    insert(found, {alias = alias, expands_to = expand or alias})
                end
            else
                sock:close()
            end
        end)
        if not ok then
            pcall(function() sock:close() end)
        end
    end
    if #found > 0 then
        local result = output_table()
        result.expn_enabled = true
        result.aliases = found
        result.alias_count = #found
        return result
    end
    return format_output(false, "EXPN not enabled")
end
