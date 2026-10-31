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
local new_socket = nmap.new_socket
local resolve = nmap.resolve

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
