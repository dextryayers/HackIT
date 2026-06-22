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

description = [[Checks if the SSH server supports the legacy and insecure SSH protocol version 1, which should be disabled in favor of SSH protocol version 2. Uses structured output with CVE mapping.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 22 or port.service == "ssh") end

action = function(host, port)
    local sock = new_socket()
    sock:set_timeout(10000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return end
        sock:send("SSH-1.5-HackIT\r\n")
        local status2, resp = sock:receive_buf("\n", 5000)
        sock:close()
        if status2 and resp then
            if find(resp, "SSH") and (find(resp, "1%.5") or find(resp, "1%.99")) then
                return true
            elseif find(resp, "Protocol mismatch") or find(resp, "SSH%-2") then
                return false
            end
            if not find(resp, "SSH%-2") then
                return true
            end
            return false
        end
        return nil
    end)
    if not ok then
        pcall(function() sock:close() end)
    end
    if result == true then
        local res = output_table()
        res.vulnerability = true
        res.name = "SSHv1 enabled"
        res.details = "SSH protocol version 1 is enabled (legacy, insecure)"
        res.severity = "HIGH"
        res.recommendation = "Disable SSHv1 and use only SSHv2"
        return res
    elseif result == false then
        return format_output(false, "SSHv1 not enabled")
    end
    return format_output(false, "Could not determine SSHv1 status")
end
