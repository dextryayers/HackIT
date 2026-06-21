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

description = [[Detects NAT by comparing TTL values and IP ID sequences.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local out = output_table()
    out.service = "NAT Detection"
    out.target = host.ip
    out.port = port.number
    local nat_indicators = {}
    if host.os and host.os_tbl and host.os_tbl.ip_id_seq then
        local seq = host.os_tbl.ip_id_seq
        out.ip_id_sequence = seq
        if seq == "ZERO" or seq == "INCREMENTAL" or seq == "BROKEN" then
            insert(nat_indicators, "IP ID sequence '" .. seq .. "' suggests NAT")
        end
    end
    if host.times and host.times.ttl then
        out.ttl = host.times.ttl
        if host.times.ttl > 0 and host.times.ttl < 64 then
            insert(nat_indicators, "TTL " .. host.times.ttl .. " (<64) — likely behind NAT")
        elseif host.times.ttl >= 64 and host.times.ttl < 128 then
            insert(nat_indicators, "TTL " .. host.times.ttl .. " — may be behind 1-layer NAT")
        end
    end
    local socket = new_socket()
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
            insert(nat_indicators, "Hop distance " .. host.os_tbl.distance .. " suggests NAT/router")
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
