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

description = [[Connects to a MySQL server and extracts the version information from the initial handshake banner packet. Uses structured output with version regex extraction.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 3306 or port.service == "mysql") end

action = function(host, port)
    local sock = new_socket()
    sock:set_timeout(10000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return end
        local banner = sock:receive_buf("", 5000)
        sock:close()
        if not banner or #banner < 5 then return end
        local protocol_version = byte(banner, 5)
        local server_version = ""
        local pos = 6
        while pos <= #banner do
            local byte = byte(banner, pos)
            if byte == 0 then break end
            server_version = server_version .. char(byte)
            pos = pos + 1
        end
        local connection_id_bytes = ""
        if pos < #banner then
            pos = pos + 1
            for i = 1, 4 do
                if pos <= #banner then
                    connection_id_bytes = connection_id_bytes .. char(byte(banner, pos))
                    pos = pos + 1
                end
            end
        end
        local res = output_table()
        res.protocol_version = protocol_version
        res.server_version = server_version
        local ver_num = match(server_version, "([%d]+%.?[%d]*%.?[%d]*)")
        if ver_num then
            res.version = ver_num
            local major, minor, patch = match(server_version, "(%d+)%.(%d+)%.(%d+)")
            if major then
                res.version_major = tonumber(major)
                res.version_minor = tonumber(minor)
                res.version_patch = tonumber(patch)
            end
        end
        if connection_id_bytes ~= "" then
            res.connection_id = connection_id_bytes
        end
        local auth_plugin = match(banner, "caching_sha2_password") or match(banner, "mysql_native_password") or match(banner, "sha256_password")
        if auth_plugin then
            res.auth_plugin = auth_plugin
        end
        return res
    end)
    if not ok then
        pcall(function() sock:close() end)
    end
    if not result then
        return format_output(false, "No MySQL banner received")
    end
    return result
end
