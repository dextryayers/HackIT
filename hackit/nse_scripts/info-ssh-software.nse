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

description = [[Retrieves SSH software version from the SSH banner.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.number == 22 end

action = function(host, port)
    local out = output_table()
    out.service = "SSH Software Detection"
    out.target = host.ip
    out.port = port.number
    local socket = new_socket()
    socket:set_timeout(5000)
    local ok, banner = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local b = socket:receive_bytes(256)
        socket:close()
        if b then
            return gsub(b, "[\r\n]+", ""):sub(1, 200)
        end
        return nil
    end)
    if not ok then pcall(socket.close, socket) end
    if banner then
        out.banner = banner
        out.version = match(banner, "SSH%-(%d%.%d)")
        if not out.version then out.version = match(banner, "([%d]+%.[%d]+)") end
        local software = "Unknown"
        if find(banner, "OpenSSH") then
            software = "OpenSSH"
            local ver = match(banner, "OpenSSH[ _]([%d.]+p?[%d]*)")
            if ver then out.software_version = ver end
        elseif find(banner, "Dropbear") then
            software = "Dropbear"
            local ver = match(banner, "Dropbear_([%d.]+)")
            if ver then out.software_version = ver end
        elseif find(banner, "libssh") then
            software = "libssh"
        elseif find(banner, "SSH") then
            software = "Generic SSH"
        end
        out.software = software
        out.status = "IDENTIFIED"
    else
        out.status = "NO_BANNER"
        out.message = "No SSH banner received"
    end
    return out
end
