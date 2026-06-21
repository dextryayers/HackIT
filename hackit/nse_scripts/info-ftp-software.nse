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

description = [[Retrieves FTP software version from the FTP banner.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.number == 21 end

action = function(host, port)
    local out = output_table()
    out.service = "FTP Software Detection"
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
            return b:gsub("[\r\n]+", ""):sub(1, 200)
        end
        return nil
    end)
    if not ok then pcall(socket.close, socket) end
    if banner then
        out.banner = banner
        local software = "Unknown"
        if banner:find("vsFTPd") then
            software = "vsFTPd"
            local ver = banner:match("vsFTPd ([%d.]+)")
            if ver then out.software_version = ver end
        elseif banner:find("ProFTPD") then
            software = "ProFTPD"
            local ver = banner:match("ProFTPD ([%d.]+)")
            if ver then out.software_version = ver end
        elseif banner:find("FileZilla") then
            software = "FileZilla Server"
            local ver = banner:match("FileZilla Server ([%d.]+)")
            if ver then out.software_version = ver end
        elseif banner:find("Pure%-FTPd") then
            software = "Pure-FTPd"
            local ver = banner:match("Pure%-FTPd ([%d.]+)")
            if ver then out.software_version = ver end
        elseif banner:find("Microsoft FTP") or banner:find("IIS") then
            software = "Microsoft IIS FTP"
            local ver = banner:match("Microsoft%-FTP%-Service/([%d.]+)")
            if ver then out.software_version = ver end
        elseif banner:find("wu%-ftpd") then
            software = "WU-FTPD"
            local ver = banner:match("wu%-(%d[%d.]+)")
            if ver then out.software_version = ver end
        elseif banner:find("Serv%-U") then
            software = "Serv-U"
            local ver = banner:match("Serv%-U ([%d.]+)")
            if ver then out.software_version = ver end
        end
        out.software = software
        out.status = "IDENTIFIED"
    else
        out.status = "NO_BANNER"
        out.message = "No FTP banner received"
    end
    return out
end
