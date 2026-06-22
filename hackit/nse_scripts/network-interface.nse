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

description = [[Detects network interfaces exposed by the target via ICMP or SNMP.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local function get_mac_vendor(mac)
    local vendors = {
        ["00:50:56"] = "VMware",
        ["00:0c:29"] = "VMware",
        ["00:05:69"] = "VMware",
        ["08:00:27"] = "Oracle VirtualBox",
        ["00:15:5d"] = "Microsoft Hyper-V",
        ["00:1a:4a"] = "Microsoft Hyper-V",
        ["ac:1f:6b"] = "Cisco",
        ["00:1d:a1"] = "Cisco",
        ["00:1a:a1"] = "Cisco",
        ["b8:88:e3"] = "Apple",
        ["3c:07:54"] = "Intel",
        ["00:14:22"] = "Dell",
        ["00:25:90"] = "HP",
    }
    if mac then
        local prefix = sub(mac, 1, 8)
        return vendors[prefix] or "Unknown"
    end
    return nil
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local out = output_table()
    out.service = "Network Interface"
    out.target_ip = host.ip
    if host.mac_addr then
        out.mac_address = host.mac_addr
        out.mac_vendor = get_mac_vendor(host.mac_addr)
    end
    if host.os and host.os_tbl then
        out.os_family = host.os_tbl.name
        out.os_accuracy = host.os_tbl.accuracy
    end
    if host.times and host.times.ttl then
        out.ttl = host.times.ttl
        if host.times.ttl <= 64 then
            out.estimated_distance = "Local (0-1 hop)"
        elseif host.times.ttl <= 128 then
            out.estimated_distance = "Medium (2-10 hops)"
        else
            out.estimated_distance = "Distant (10+ hops)"
        end
    end
    out.port_open = port.number
    out.port_protocol = port.protocol
    return out
end
