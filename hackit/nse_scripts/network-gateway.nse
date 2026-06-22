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

description = [[Detects the default gateway via ICMP, ARP, or routing protocol analysis.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local function detect_gateway_raw()
    local socket = new_socket("raw")
    socket:set_timeout(3000)
    local ok, resp = pcall(function()
        local arp_req = char(0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01)
        arp_req = arp_req .. rep(char(0), 6) .. char(0x0a, 0x00, 0x00, 0x02)
        arp_req = arp_req .. rep(char(0), 6) .. char(0x0a, 0x00, 0x00, 0x01)
        socket:send(arp_req)
        local _, r = socket:receive_bytes(128)
        socket:close()
        return r
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return resp
end

local function probe_traceroute(host, port)
    local socket = new_socket()
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
    local out = output_table()
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
        for octet in host.gmatch(ip, "(%d+)") do
            insert(addr_octets, tonumber(octet))
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
        local gateway_match = match(trace_result, "([%d%.]+)")
        if gateway_match then out.traceroute_gateway = gateway_match end
    end
    return out
end
