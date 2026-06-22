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

description = [[Discovers hostname via reverse DNS, SMTP EHLO, or HTTP Host header.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local function probe_smtp(host, port)
    local socket = new_socket()
    socket:set_timeout(5000)
    local ok, resp = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local banner = socket:receive_bytes(128)
        socket:send("EHLO probe\r\n")
        local r = socket:receive_bytes(512)
        socket:send("HELO probe\r\n")
        local r2 = socket:receive_bytes(256)
        socket:close()
        return (banner or "") .. (r or "") .. (r2 or "")
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return resp
end

local function probe_http(host, port)
    local socket = new_socket()
    socket:set_timeout(5000)
    local ok, resp = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        socket:send("GET / HTTP/1.1\r\nHost: " .. host.ip .. "\r\nConnection: close\r\n\r\n")
        local r = socket:receive_bytes(4096)
        socket:close()
        return r
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return resp
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local out = output_table()
    out.service = "Hostname Discovery"
    out.target = host.ip
    out.port = port.number
    local hostnames = {}
    if host.name and host.name ~= "" then
        insert(hostnames, {source = "Reverse DNS", hostname = host.name})
    end
    if port.number == 25 or port.number == 587 then
        local resp = probe_smtp(host, port)
        if resp then
            local ehlo_host = match(resp, "([%w._-]+[%.][%a][%a]+)")
            if ehlo_host then
                insert(hostnames, {source = "SMTP EHLO", hostname = gsub(ehlo_host, "^[\r\n%s]+", "")})
            end
            local banner_host = match(resp, "ESMTP ([%w._-]+)")
            if banner_host then
                insert(hostnames, {source = "SMTP Banner", hostname = banner_host})
            end
        end
    end
    if port.number == 80 or port.number == 8080 or port.number == 443 then
        local resp = probe_http(host, port)
        if resp then
            local server = match(resp, "Server: ([^\r\n]+)")
            if server then
                local host_part = match(server, "[%w._-]+%.[%a][%a]+")
                if host_part then
                    insert(hostnames, {source = "HTTP Server Header", hostname = host_part})
                end
            end
            local host_hdr = match(resp, "^Host: ([^\r\n]+)")
            if host_hdr then
                insert(hostnames, {source = "HTTP Host Header", hostname = host_hdr})
            end
        end
    end
    if #hostnames > 0 then
        out.status = "HOSTNAME_FOUND"
        out.hostnames = hostnames
        out.primary_hostname = hostnames[1].hostname
    else
        out.status = "NOT_FOUND"
        out.message = "No hostname discovered via available methods"
    end
    return out
end
