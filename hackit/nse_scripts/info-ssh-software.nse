local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Retrieves SSH software version from the SSH banner.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.number == 22 end

action = function(host, port)
    local out = stdnse.output_table()
    out.service = "SSH Software Detection"
    out.target = host.ip
    out.port = port.number
    local socket = nmap.new_socket()
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
        out.version = banner:match("SSH%-(%d%.%d)")
        if not out.version then out.version = banner:match("([%d]+%.[%d]+)") end
        local software = "Unknown"
        if banner:find("OpenSSH") then
            software = "OpenSSH"
            local ver = banner:match("OpenSSH[ _]([%d.]+p?[%d]*)")
            if ver then out.software_version = ver end
        elseif banner:find("Dropbear") then
            software = "Dropbear"
            local ver = banner:match("Dropbear_([%d.]+)")
            if ver then out.software_version = ver end
        elseif banner:find("libssh") then
            software = "libssh"
        elseif banner:find("SSH") then
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
