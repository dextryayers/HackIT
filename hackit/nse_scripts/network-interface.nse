local stdnse = require "stdnse"
local nmap = require "nmap"
local shortport = require "shortport"



-- Fast-path bindings for the stdlib and nmap API used by this script.
-- Kept strict-mode safe: every name below is a declared local.
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
local move = table.move
local tostring = tostring
local tonumber = tonumber
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local unpack = table.unpack
local setmetatable = setmetatable
local getmetatable = getmetatable
local error = error
local select = select

local clock = nmap.clock
local msleep = function(ms)
    if stdnse and stdnse.sleep then
        return stdnse.sleep((ms or 0) / 1000)
    end
    if nmap.msleep then
        return nmap.msleep(ms or 0)
    end
    local deadline = nmap.clock() + (ms or 0) / 1000
    while nmap.clock() < deadline do end
    return true
end
local new_socket = nmap.new_socket
local resolve = nmap.resolve

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    if stdnse and stdnse.sleep then
        return stdnse.sleep(seconds)
    end
    if nmap.msleep then
        return nmap.msleep(math.max(0, math.floor((seconds or 0) * 1000)))
    end
    local deadline = nmap.clock() + (seconds or 0)
    while nmap.clock() < deadline do end
    return true
end

local strsplit = function(sep, str, max)
    local out, pos, n = {}, 1, 0
    if str == nil then return out end
    while true do
        if max and n >= max - 1 then
            out[#out + 1] = sub(str, pos)
            return out
        end
        local s, e = find(str, sep, pos)
        if not s then
            out[#out + 1] = sub(str, pos)
            return out
        end
        if e < pos then e = pos end
        out[#out + 1] = sub(str, pos, s - 1)
        pos = e + 1
        n = n + 1
        if pos > #str then
            out[#out + 1] = ""
            return out
        end
    end
end

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
