local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Discovers DHCPv6 servers and prefixes on the local network.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local all_dhcp_servers = "ff02::1:2"

local function dhcpv6_solicit(timeout)
    timeout = timeout or 5000
    local socket = nmap.new_socket("raw")
    socket:set_timeout(timeout)
    local ok, resp = pcall(function()
        local msg_type = string.char(0x01)
        local transaction_id = string.char(math.random(0, 255), math.random(0, 255), math.random(0, 255))
        local dhcpv6 = msg_type .. transaction_id
        local option_code = string.char(0x00, 0x01)
        local option_len = string.char(0x00, 0x04)
        local iaid = string.char(0x00, 0x00, 0x00, 0x01)
        local t1 = string.char(0x00, 0x00, 0x00, 0x00)
        local t2 = string.char(0x00, 0x00, 0x00, 0x00)
        local ia_na = option_code .. option_len .. iaid .. t1 .. t2
        local elapsed_code = string.char(0x00, 0x08)
        local elapsed_len = string.char(0x00, 0x02)
        local elapsed_time = string.char(0x00, 0x00)
        dhcpv6 = dhcpv6 .. ia_na .. elapsed_code .. elapsed_len .. elapsed_time
        local opt_req_code = string.char(0x00, 0x06)
        local opt_req_len = string.char(0x00, 0x02)
        local dns_opt = string.char(0x00, 0x17)
        dhcpv6 = dhcpv6 .. opt_req_code .. opt_req_len .. dns_opt
        socket:send(dhcpv6)
        local _, r = socket:receive_bytes(1024)
        socket:close()
        local result = nil
        if r and #r > 10 then
            result = {}
            result.received = true
            result.length = #r
            result.msg_type = r:byte(1)
            if r:byte(1) == 2 then result.message = "DHCPv6 ADVERTISE" end
            if r:byte(1) == 7 then result.message = "DHCPv6 REPLY" end
            local pos = 5
            while pos < #r - 3 do
                local opt = (r:byte(pos) or 0) * 256 + (r:byte(pos + 1) or 0)
                local optlen = (r:byte(pos + 2) or 0) * 256 + (r:byte(pos + 3) or 0)
                if optlen < 1 or optlen > #r - pos + 1 then break end
                local val = r:sub(pos + 4, pos + optlen - 1)
                if opt == 23 then
                    result.dns_servers = result.dns_servers or {}
                    result.dns_servers[#result.dns_servers + 1] = val
                end
                if opt == 25 then
                    result.ntp_servers = result.ntp_servers or {}
                    result.ntp_servers[#result.ntp_servers + 1] = val
                end
                if opt == 7 then
                    result.preferred_lifetime = (r:byte(pos + 4) or 0) * 256^3 + (r:byte(pos + 5) or 0) * 256^2 + (r:byte(pos + 6) or 0) * 256 + (r:byte(pos + 7) or 0)
                    result.valid_lifetime = (r:byte(pos + 8) or 0) * 256^3 + (r:byte(pos + 9) or 0) * 256^2 + (r:byte(pos + 10) or 0) * 256 + (r:byte(pos + 11) or 0)
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
    local out = stdnse.output_table()
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
