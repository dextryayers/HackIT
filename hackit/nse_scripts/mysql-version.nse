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
