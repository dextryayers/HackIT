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

description = [[Connects to an SSH server and enumerates supported authentication methods by sending an authentication request with the "none" method and parsing the response for supported methods.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 22 or port.service == "ssh") end

action = function(host, port)
    local sock = new_socket()
    sock:set_timeout(10000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return end
        local banner = sock:receive_buf("\n", 5000)
        if not banner then sock:close(); return end
        sock:send("SSH-2.0-HackIT\r\n")
        local kex = sock:receive_buf("\n", 5000)
        if not kex then sock:close(); return end
        local ssh_packet = char(0x05, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        sock:send(ssh_packet)
        local _, resp = sock:receive_buf("\n", 5000)
        sock:close()
        if resp then
            local methods = {}
            if match(resp, "publickey") then insert(methods, "publickey") end
            if match(resp, "password") then insert(methods, "password") end
            if match(resp, "keyboard%-interactive") then insert(methods, "keyboard-interactive") end
            if match(resp, "hostbased") then insert(methods, "hostbased") end
            if match(resp, "gssapi") then insert(methods, "gssapi-with-mic") end
            if match(resp, "none") then insert(methods, "none") end
            local res = output_table()
            res.supported_auth_methods = methods
            res.banner = match(banner, "([^\r\n]+)")
            res.ssh_version = match(banner, "SSH%-(%S+)")
            return res
        end
        return nil
    end)
    if not ok then
        pcall(function() sock:close() end)
    end
    if not result then
        return format_output(false, "Could not enumerate auth methods")
    end
    return result
end
