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

description = [[Discovers DHCPv6 servers and prefixes on the local network.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local all_dhcp_servers = "ff02::1:2"

local function dhcpv6_solicit(timeout)
    timeout = timeout or 5000
    local socket = new_socket("raw")
    socket:set_timeout(timeout)
    local ok, resp = pcall(function()
        local msg_type = char(0x01)
        local transaction_id = char(math.random(0, 255), math.random(0, 255), math.random(0, 255))
        local dhcpv6 = msg_type .. transaction_id
        local option_code = char(0x00, 0x01)
        local option_len = char(0x00, 0x04)
        local iaid = char(0x00, 0x00, 0x00, 0x01)
        local t1 = char(0x00, 0x00, 0x00, 0x00)
        local t2 = char(0x00, 0x00, 0x00, 0x00)
        local ia_na = option_code .. option_len .. iaid .. t1 .. t2
        local elapsed_code = char(0x00, 0x08)
        local elapsed_len = char(0x00, 0x02)
        local elapsed_time = char(0x00, 0x00)
        dhcpv6 = dhcpv6 .. ia_na .. elapsed_code .. elapsed_len .. elapsed_time
        local opt_req_code = char(0x00, 0x06)
        local opt_req_len = char(0x00, 0x02)
        local dns_opt = char(0x00, 0x17)
        dhcpv6 = dhcpv6 .. opt_req_code .. opt_req_len .. dns_opt
        socket:send(dhcpv6)
        local _, r = socket:receive_bytes(1024)
        socket:close()
        local result = nil
        if r and #r > 10 then
            result = {}
            result.received = true
            result.length = #r
            result.msg_type = byte(r, 1)
            if byte(r, 1) == 2 then result.message = "DHCPv6 ADVERTISE" end
            if byte(r, 1) == 7 then result.message = "DHCPv6 REPLY" end
            local pos = 5
            while pos < #r - 3 do
                local opt = (byte(r, pos) or 0) * 256 + (byte(r, pos + 1) or 0)
                local optlen = (byte(r, pos + 2) or 0) * 256 + (byte(r, pos + 3) or 0)
                if optlen < 1 or optlen > #r - pos + 1 then break end
                local val = sub(r, pos + 4, pos + optlen - 1)
                if opt == 23 then
                    result.dns_servers = result.dns_servers or {}
                    result.dns_servers[#result.dns_servers + 1] = val
                end
                if opt == 25 then
                    result.ntp_servers = result.ntp_servers or {}
                    result.ntp_servers[#result.ntp_servers + 1] = val
                end
                if opt == 7 then
                    result.preferred_lifetime = (byte(r, pos + 4) or 0) * 256^3 + (byte(r, pos + 5) or 0) * 256^2 + (byte(r, pos + 6) or 0) * 256 + (byte(r, pos + 7) or 0)
                    result.valid_lifetime = (byte(r, pos + 8) or 0) * 256^3 + (byte(r, pos + 9) or 0) * 256^2 + (byte(r, pos + 10) or 0) * 256 + (byte(r, pos + 11) or 0)
                end
                pos = pos + optlen
            end
        end
        return result
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return resp
end

portrule = function(host, port) return port.protocol == "udp" and port.state == "open" and port.number == 547 end

action = function(host, port)
    local out = output_table()
    out.service = "DHCPv6"
    out.multicast_group = all_dhcp_servers
    local result = dhcpv6_solicit(5000)
    if result and result.received then
        out.status = "SERVER_FOUND"
        out.server_present = true
        out.response_length = result.length
        out.message_type = result.message
        if result.dns_servers then out.dns_servers = result.dns_servers end
        if result.ntp_servers then out.ntp_servers = result.ntp_servers end
        if result.preferred_lifetime then out.preferred_lifetime = result.preferred_lifetime end
        if result.valid_lifetime then out.valid_lifetime = result.valid_lifetime end
    else
        out.status = "NO_SERVER"
        out.server_present = false
        out.message = "No DHCPv6 server detected"
    end
    return out
end
