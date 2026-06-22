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

description = [[Discovers DHCP servers on the local network by sending DHCPDISCOVER.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local function dhcp_discover(timeout)
    timeout = timeout or 5000
    local socket = new_socket("udp")
    socket:set_timeout(timeout)
    local ok, resp = pcall(function()
        socket:connect("255.255.255.255", 67, "udp")
        local xid = char(math.random(0, 255), math.random(0, 255), math.random(0, 255), math.random(0, 255))
        local mac = char(math.random(0, 255), math.random(0, 255), math.random(0, 255), math.random(0, 255), math.random(0, 255), math.random(0, 255))
        local dhcp = char(1, 1, 6, 0) .. xid .. char(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        dhcp = dhcp .. char(0, 0, 0, 0) .. mac .. rep(char(0), 10)
        dhcp = dhcp .. rep(char(0), 64)
        dhcp = dhcp .. char(0x63, 0x82, 0x53, 0x63)
        dhcp = dhcp .. char(0x35, 0x01, 0x01)
        dhcp = dhcp .. char(0x3d, 0x07, 0x01) .. mac
        dhcp = dhcp .. char(0xff)
        socket:send(dhcp)
        local _, r = socket:receive_bytes(512)
        socket:close()
        local result = {}
        if r and #r > 0 then
            result.response_received = true
            result.response_size = #r
            if byte(r, 2) == 2 then result.message_type = "DHCPOFFER" end
            if byte(r, 2) == 4 then result.message_type = "DHCPACK" end
            if #r >= 20 then
                local yiaddr = byte(r, 16) .. "." .. byte(r, 17) .. "." .. byte(r, 18) .. "." .. byte(r, 19)
                result.offered_ip = yiaddr
            end
            for i = 1, #r - 3 do
                if byte(r, i) == 0x36 and byte(r, i+1) == 0x04 then
                    local sip = byte(r, i+2) .. "." .. byte(r, i+3) .. "." .. byte(r, i+4) .. "." .. byte(r, i+5)
                    result.dhcp_server_ip = sip
                end
            end
        end
        return result
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return resp
end

portrule = function(host, port) return port.protocol == "udp" and port.state == "open" and port.number == 67 end

action = function(host, port)
    local out = output_table()
    out.service = "DHCP Server Detection"
    out.probed_from = host.ip
    local result = dhcp_discover(5000)
    if result and result.response_received then
        out.status = "FOUND"
        out.dhcp_server = not not result.dhcp_server_ip
        if result.dhcp_server_ip then out.server_ip = result.dhcp_server_ip end
        if result.offered_ip then out.offered_ip = result.offered_ip end
        if result.message_type then out.message_type = result.message_type end
        out.response_size_bytes = result.response_size
    else
        out.status = "NOT_FOUND"
        out.message = "No DHCP server responded to DISCOVER"
    end
    return out
end
