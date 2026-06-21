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
            if resp:find("Microsoft") or resp:find("MS") or resp:find("SQL Server") then
                res.server = "Microsoft SQL Server"
            end
            local version_bytes = resp:sub(37, 40)
            local parts = {}
            for i = 1, #version_bytes do
                insert(parts, tostring(byte(version_bytes, i)))
            end
            res.version_raw = concat(parts, ".")
            local ver_str = resp:match("version[%s:=]+([%d%.]+)") or resp:match("SQL Server (%d%d%d%d)")
            if ver_str then
                res.version = ver_str
                local major = ver_str:match("^(%d+)")
                if major then res.version_major = tonumber(major) end
            end
            local instance = resp:match("InstanceName[^\x00]*[\x00]([^\x00]+)")
            if instance then res.instance_name = instance end
            local server_name = resp:match("ServerName[^\x00]*[\x00]([^\x00]+)")
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
