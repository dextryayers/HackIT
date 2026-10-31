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

description = [[Connects to Microsoft SQL Server and retrieves server information such as version, instance name, and configured options via the pre-login handshake. Uses structured output with version extraction.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 1433 or port.service == "ms-sql-s") end

local function build_prelogin()
    return char(
        0x02, 0x01, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    )
end

action = function(host, port)
    local sock = new_socket()
    sock:set_timeout(10000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return end
        sock:send(build_prelogin())
        local _, resp = sock:receive_buf("", 5000)
        sock:close()
        if resp and #resp > 20 then
            local res = output_table()
            if find(resp, "Microsoft") or find(resp, "MS") or find(resp, "SQL Server") then
                res.server = "Microsoft SQL Server"
            end
            local version_bytes = sub(resp, 37, 40)
            local parts = {}
            for i = 1, #version_bytes do
                insert(parts, tostring(byte(version_bytes, i)))
            end
            res.version_raw = concat(parts, ".")
            local ver_str = match(resp, "version[%s:=]+([%d%.]+)") or match(resp, "SQL Server (%d%d%d%d)")
            if ver_str then
                res.version = ver_str
                local major = match(ver_str, "^(%d+)")
                if major then res.version_major = tonumber(major) end
            end
            local instance = match(resp, "InstanceName[^\x00]*[\x00]([^\x00]+)")
            if instance then res.instance_name = instance end
            local server_name = match(resp, "ServerName[^\x00]*[\x00]([^\x00]+)")
            if server_name then res.server_name = server_name end
            return res
        end
    end)
    if not ok then
        pcall(function() sock:close() end)
    end
    if not result then
        return format_output(false, "Could not retrieve MSSQL info")
    end
    return result
end
