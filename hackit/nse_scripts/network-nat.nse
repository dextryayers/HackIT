local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Detects NAT by comparing TTL values and IP ID sequences.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local out = stdnse.output_table()
    out.service = "NAT Detection"
    out.target = host.ip
    out.port = port.number
    local nat_indicators = {}
    if host.os and host.os_tbl and host.os_tbl.ip_id_seq then
        local seq = host.os_tbl.ip_id_seq
        out.ip_id_sequence = seq
        if seq == "ZERO" or seq == "INCREMENTAL" or seq == "BROKEN" then
            nat_indicators[#nat_indicators + 1] = "IP ID sequence '" .. seq .. "' suggests NAT"
        end
    end
    if host.times and host.times.ttl then
        out.ttl = host.times.ttl
        if host.times.ttl > 0 and host.times.ttl < 64 then
            nat_indicators[#nat_indicators + 1] = "TTL " .. host.times.ttl .. " (<64) — likely behind NAT"
        elseif host.times.ttl >= 64 and host.times.ttl < 128 then
            nat_indicators[#nat_indicators + 1] = "TTL " .. host.times.ttl .. " — may be behind 1-layer NAT"
        end
    end
    local socket = nmap.new_socket()
    socket:set_timeout(3000)
    local ok, resp = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local initial = socket:get_status()
        socket:close()
        return initial
    end)
    if not ok then pcall(socket.close, socket) end
    if host.os and host.os_tbl and host.os_tbl.distance then
        out.hop_distance = host.os_tbl.distance
        if host.os_tbl.distance > 1 then
            nat_indicators[#nat_indicators + 1] = "Hop distance " .. host.os_tbl.distance .. " suggests NAT/router"
        end
    end
    if #nat_indicators > 0 then
        out.nat_detected = true
        out.indicators = nat_indicators
    else
        out.nat_detected = false
        out.message = "No NAT signs detected"
    end
    return out
end
