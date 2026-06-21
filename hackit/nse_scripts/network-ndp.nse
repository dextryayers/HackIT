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

description = [[Detects Neighbor Discovery Protocol (NDP) messages — the IPv6 equivalent of ARP.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local function probe_ndp_raw(timeout)
    timeout = timeout or 5000
    local socket = new_socket("raw")
    socket:set_timeout(timeout)
    local ok, resp = pcall(function()
        local ns_type = char(0x87)
        local code = char(0x00)
        local checksum = char(0x00, 0x00)
        local reserved = char(0x00, 0x00, 0x00, 0x00)
        local target = char(0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
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
                for i = 9, 24 do target_addr = target_addr .. format("%02x", r:byte(i)) if i % 2 == 0 and i < 24 then target_addr = target_addr .. ":" end end
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
    local out = output_table()
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
