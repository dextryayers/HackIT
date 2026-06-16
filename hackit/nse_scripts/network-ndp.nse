local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Detects Neighbor Discovery Protocol (NDP) messages — the IPv6 equivalent of ARP.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local function probe_ndp_raw(timeout)
    timeout = timeout or 5000
    local socket = nmap.new_socket("raw")
    socket:set_timeout(timeout)
    local ok, resp = pcall(function()
        local ns_type = string.char(0x87)
        local code = string.char(0x00)
        local checksum = string.char(0x00, 0x00)
        local reserved = string.char(0x00, 0x00, 0x00, 0x00)
        local target = string.char(0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
        local ns = ns_type .. code .. checksum .. reserved .. target
        socket:send(ns)
        local _, r = socket:receive_bytes(256)
        socket:close()
        local result = nil
        if r and #r >= 16 then
            result = {}
            result.received = true
            result.length = #r
            result.icmpv6_type = r:byte(1)
            if r:byte(1) == 0x88 then result.message_type = "Neighbor Advertisement (NA)" end
            if r:byte(1) == 0x87 then result.message_type = "Neighbor Solicitation (NS)" end
            if r:byte(1) == 0x86 then result.message_type = "Router Solicitation (RS)" end
            if r:byte(1) == 0x85 then result.message_type = "Router Advertisement (RA)" end
            if #r >= 24 then
                local target_addr = ""
                for i = 9, 24 do target_addr = target_addr .. string.format("%02x", r:byte(i)) if i % 2 == 0 and i < 24 then target_addr = target_addr .. ":" end end
                result.target_address = target_addr
            end
        end
        return result
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return resp
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local out = stdnse.output_table()
    out.service = "NDP Detection"
    out.target = host.ip
    out.ipv6_present = (host.ip and host.ip:match(":")) ~= nil
    local result = probe_ndp_raw(5000)
    if result and result.received then
        out.status = "NDP_ACTIVE"
        out.ndp_messages = true
        out.response_length = result.length
        out.icmpv6_type = result.icmpv6_type
        out.message_type = result.message_type
        if result.target_address then out.target_address = result.target_address end
    else
        out.status = "NO_NDP"
        out.ndp_messages = false
        if out.ipv6_present then
            out.message = "No NDP activity detected on IPv6"
        else
            out.message = "No NDP activity detected (IPv4 only target)"
        end
    end
    return out
end
