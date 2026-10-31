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

description = [[Tests if the FTP server allows anonymous login using "anonymous" or "ftp" as the username with any password. Uses structured output with version extraction from banner.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 21 or port.service == "ftp") end

local credentials = {
    {"anonymous", "guest@"},
    {"ftp", "ftp@"},
    {"anonymous", "anonymous@"},
    {"ftp", "password"},
}

action = function(host, port)
    local sock = new_socket()
    sock:set_timeout(10000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return end
        local banner = sock:receive_buf("\n", 5000)
        if not banner then sock:close(); return end
        local found_access = false
        local last_msg
        for _, cred in ipairs(credentials) do
            local s = new_socket()
            s:set_timeout(5000)
            local ok2 = s:connect(host.ip, port)
            if ok2 then
                s:receive_buf("\n", 3000)
                s:send("USER " .. cred[1] .. "\r\n")
                s:receive_buf("\n", 3000)
                s:send("PASS " .. cred[2] .. "\r\n")
                local _, r = s:receive_buf("\n", 3000)
                s:close()
                if r and (match(r, "230 ") or match(r, "User logged in")) then
                    found_access = true
                    last_msg = r
                    break
                end
            end
        end
        sock:close()
        local res = output_table()
        res.banner = match(banner, "220[%s-]([^\r\n]+)") or match(banner, "220([^\r\n]+)")
        res.anonymous_access = found_access
        local ver = match(banner, "([%d%.]+)[%s_]?ftp") or match(banner, "FTP%s+version%s+([%d%.]+)") or match(banner, "vsFTP[d]%s+([%d%.]+)")
        if ver then res.version = ver end
        if found_access then
            if last_msg then
                res.message = match(last_msg, "%d%d%d ([^\r\n]+)")
            end
        end
        return res
    end)
    if not ok then
        pcall(function() sock:close() end)
    end
    if not result then
        return format_output(false, "Could not test FTP anonymous access")
    end
    return result
end
