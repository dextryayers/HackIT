local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Discovers hostname via reverse DNS, SMTP EHLO, or HTTP Host header.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local function probe_smtp(host, port)
    local socket = nmap.new_socket()
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
    local socket = nmap.new_socket()
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
    local out = stdnse.output_table()
    out.service = "Hostname Discovery"
    out.target = host.ip
    out.port = port.number
    local hostnames = {}
    if host.name and host.name ~= "" then
        hostnames[#hostnames + 1] = {source = "Reverse DNS", hostname = host.name}
    end
    if port.number == 25 or port.number == 587 then
        local resp = probe_smtp(host, port)
        if resp then
            local ehlo_host = resp:match("([%w._-]+[%.][%a][%a]+)")
            if ehlo_host then
                hostnames[#hostnames + 1] = {source = "SMTP EHLO", hostname = ehlo_host:gsub("^[\r\n%s]+", "")}
            end
            local banner_host = resp:match("ESMTP ([%w._-]+)")
            if banner_host then
                hostnames[#hostnames + 1] = {source = "SMTP Banner", hostname = banner_host}
            end
        end
    end
    if port.number == 80 or port.number == 8080 or port.number == 443 then
        local resp = probe_http(host, port)
        if resp then
            local server = resp:match("Server: ([^\r\n]+)")
            if server then
                local host_part = server:match("[%w._-]+%.[%a][%a]+")
                if host_part then
                    hostnames[#hostnames + 1] = {source = "HTTP Server Header", hostname = host_part}
                end
            end
            local host_hdr = resp:match("^Host: ([^\r\n]+)")
            if host_hdr then
                hostnames[#hostnames + 1] = {source = "HTTP Host Header", hostname = host_hdr}
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
