local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Detects the default gateway via ICMP, ARP, or routing protocol analysis.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local function detect_gateway_raw()
    local socket = nmap.new_socket("raw")
    socket:set_timeout(3000)
    local ok, resp = pcall(function()
        local arp_req = string.char(0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01)
        arp_req = arp_req .. string.rep(string.char(0), 6) .. string.char(0x0a, 0x00, 0x00, 0x02)
        arp_req = arp_req .. string.rep(string.char(0), 6) .. string.char(0x0a, 0x00, 0x00, 0x01)
        socket:send(arp_req)
        local _, r = socket:receive_bytes(128)
        socket:close()
        return r
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return resp
end

local function probe_traceroute(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(3000)
    local ok, resp = pcall(function()
        socket:connect(host, port)
        socket:send("TRACEROUTE\r\n")
        local _, r = socket:receive_bytes(256)
        socket:close()
        return r
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return resp
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local out = stdnse.output_table()
    out.service = "Gateway Detection"
    out.target_ip = host.ip
    if host.times and host.times.ttl then
        out.ttl = host.times.ttl
        if host.times.ttl <= 64 then
            out.gateway_proximity = "Likely same subnet"
            out.estimated_hops = 1
        elseif host.times.ttl <= 128 then
            out.gateway_proximity = "Some hops away"
            out.estimated_hops = 2
        else
            out.gateway_proximity = "Multiple hops"
            out.estimated_hops = 3
        end
    end
    local addr_octets = {}
    if host.ip then
        for octet in host.ip:gmatch("(%d+)") do
            addr_octets[#addr_octets + 1] = tonumber(octet)
        end
        if #addr_octets == 4 then
            local subnet = addr_octets[1] .. "." .. addr_octets[2] .. "." .. addr_octets[3]
            out.subnet = subnet .. ".0/24"
            out.likely_gateway = subnet .. ".1"
            out.alternate_gateway = subnet .. ".254"
        end
    end
    local raw_result = detect_gateway_raw()
    if raw_result then
        out.arp_response = true
    end
    local trace_result = probe_traceroute(host, port)
    if trace_result then
        out.traceroute_response = true
        local gateway_match = trace_result:match("([%d%.]+)")
        if gateway_match then out.traceroute_gateway = gateway_match end
    end
    return out
end
