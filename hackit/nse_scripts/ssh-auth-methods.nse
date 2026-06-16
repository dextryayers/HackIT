local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Connects to an SSH server and enumerates supported authentication methods by sending an authentication request with the "none" method and parsing the response for supported methods.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 22 or port.service == "ssh") end

action = function(host, port)
    local sock = nmap.new_socket()
    sock:set_timeout(10000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return end
        local banner = sock:receive_buf("\n", 5000)
        if not banner then sock:close(); return end
        sock:send("SSH-2.0-HackIT\r\n")
        local kex = sock:receive_buf("\n", 5000)
        if not kex then sock:close(); return end
        local ssh_packet = string.char(0x05, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        sock:send(ssh_packet)
        local _, resp = sock:receive_buf("\n", 5000)
        sock:close()
        if resp then
            local methods = {}
            if resp:match("publickey") then table.insert(methods, "publickey") end
            if resp:match("password") then table.insert(methods, "password") end
            if resp:match("keyboard%-interactive") then table.insert(methods, "keyboard-interactive") end
            if resp:match("hostbased") then table.insert(methods, "hostbased") end
            if resp:match("gssapi") then table.insert(methods, "gssapi-with-mic") end
            if resp:match("none") then table.insert(methods, "none") end
            local res = stdnse.output_table()
            res.supported_auth_methods = methods
            res.banner = banner:match("([^\r\n]+)")
            res.ssh_version = banner:match("SSH%-(%S+)")
            return res
        end
        return nil
    end)
    if not ok then
        pcall(function() sock:close() end)
    end
    if not result then
        return stdnse.format_output(false, "Could not enumerate auth methods")
    end
    return result
end
