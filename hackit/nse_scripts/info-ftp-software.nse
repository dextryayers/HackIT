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
            return gsub(b, "[\r\n]+", ""):sub(1, 200)
        end
        return nil
    end)
    if not ok then pcall(socket.close, socket) end
    if banner then
        out.banner = banner
        local software = "Unknown"
        if find(banner, "vsFTPd") then
            software = "vsFTPd"
            local ver = match(banner, "vsFTPd ([%d.]+)")
            if ver then out.software_version = ver end
        elseif find(banner, "ProFTPD") then
            software = "ProFTPD"
            local ver = match(banner, "ProFTPD ([%d.]+)")
            if ver then out.software_version = ver end
        elseif find(banner, "FileZilla") then
            software = "FileZilla Server"
            local ver = match(banner, "FileZilla Server ([%d.]+)")
            if ver then out.software_version = ver end
        elseif find(banner, "Pure%-FTPd") then
            software = "Pure-FTPd"
            local ver = match(banner, "Pure%-FTPd ([%d.]+)")
            if ver then out.software_version = ver end
        elseif find(banner, "Microsoft FTP") or find(banner, "IIS") then
            software = "Microsoft IIS FTP"
            local ver = match(banner, "Microsoft%-FTP%-Service/([%d.]+)")
            if ver then out.software_version = ver end
        elseif find(banner, "wu%-ftpd") then
            software = "WU-FTPD"
            local ver = match(banner, "wu%-(%d[%d.]+)")
            if ver then out.software_version = ver end
        elseif find(banner, "Serv%-U") then
            software = "Serv-U"
            local ver = match(banner, "Serv%-U ([%d.]+)")
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
