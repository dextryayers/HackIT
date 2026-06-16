local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Discovers DHCP servers on the local network by sending DHCPDISCOVER.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local function dhcp_discover(timeout)
    timeout = timeout or 5000
    local socket = nmap.new_socket("udp")
    socket:set_timeout(timeout)
    local ok, resp = pcall(function()
        socket:connect("255.255.255.255", 67, "udp")
        local xid = string.char(math.random(0, 255), math.random(0, 255), math.random(0, 255), math.random(0, 255))
        local mac = string.char(math.random(0, 255), math.random(0, 255), math.random(0, 255), math.random(0, 255), math.random(0, 255), math.random(0, 255))
        local dhcp = string.char(1, 1, 6, 0) .. xid .. string.char(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        dhcp = dhcp .. string.char(0, 0, 0, 0) .. mac .. string.rep(string.char(0), 10)
        dhcp = dhcp .. string.rep(string.char(0), 64)
        dhcp = dhcp .. string.char(0x63, 0x82, 0x53, 0x63)
        dhcp = dhcp .. string.char(0x35, 0x01, 0x01)
        dhcp = dhcp .. string.char(0x3d, 0x07, 0x01) .. mac
        dhcp = dhcp .. string.char(0xff)
        socket:send(dhcp)
        local _, r = socket:receive_bytes(512)
        socket:close()
        local result = {}
        if r and #r > 0 then
            result.response_received = true
            result.response_size = #r
            if r:byte(2) == 2 then result.message_type = "DHCPOFFER" end
            if r:byte(2) == 4 then result.message_type = "DHCPACK" end
            if #r >= 20 then
                local yiaddr = string.byte(r, 16) .. "." .. string.byte(r, 17) .. "." .. string.byte(r, 18) .. "." .. string.byte(r, 19)
                result.offered_ip = yiaddr
            end
            for i = 1, #r - 3 do
                if r:byte(i) == 0x36 and r:byte(i+1) == 0x04 then
                    local sip = string.byte(r, i+2) .. "." .. string.byte(r, i+3) .. "." .. string.byte(r, i+4) .. "." .. string.byte(r, i+5)
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
    local out = stdnse.output_table()
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
