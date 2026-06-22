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

description = [[Analyzes the multicast routing table by probing for IGMP/PIM messages.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local igmp_types = {
    [0x11] = "Membership Query",
    [0x12] = "IGMP v1 Report",
    [0x16] = "IGMP v2 Report",
    [0x17] = "IGMP v2 Leave",
    [0x22] = "IGMP v3 Report",
}

local function igmp_probe(timeout)
    timeout = timeout or 5000
    local socket = new_socket("raw")
    socket:set_timeout(timeout)
    local ok, resp = pcall(function()
        local igmp_type = char(0x11)
        local code = char(0x00)
        local checksum = char(0x00, 0x00)
        local group = char(0xe0, 0x00, 0x00, 0x01)
        local igmp = igmp_type .. code .. checksum .. group
        socket:send(igmp)
        local _, r = socket:receive_bytes(512)
        socket:close()
        local result = nil
        if r and #r >= 8 then
            result = {}
            result.received = true
            result.length = #r
            local rtype = byte(r, 1) or 0
            result.igmp_type = rtype
            result.igmp_type_name = igmp_types[rtype] or ("Unknown (0x" .. format("%02x", rtype) .. ")")
            if #r >= 8 then
                local group_addr = byte(r, 5) .. "." .. byte(r, 6) .. "." .. byte(r, 7) .. "." .. byte(r, 8)
                result.group_address = group_addr
            end
            if rtype == 0x22 and #r > 12 then
                result.sources = (byte(r, 11) or 0) * 256 + (byte(r, 12) or 0)
            end
        end
        return result
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return resp
end

local function pim_probe(timeout)
    timeout = timeout or 5000
    local socket = new_socket("raw")
    socket:set_timeout(timeout)
    local ok, resp = pcall(function()
        local pim_type = char(0x20)
        local pim = pim_type
        socket:send(pim)
        local _, r = socket:receive_bytes(256)
        socket:close()
        local result = nil
        if r and #r > 4 then
            result = {}
            result.received = true
            result.length = #r
            local ver_type = byte(r, 1) or 0
            local pim_ver = (ver_type >> 4) & 0x0F
            result.pim_version = pim_ver
        end
        return result
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return resp
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local out = output_table()
    out.service = "Multicast Routing Detection"
    out.target = host.ip
    local igmp = igmp_probe(5000)
    local pim = pim_probe(5000)
    local protocols = {}
    if igmp and igmp.received then
        insert(protocols, "IGMP")
        out.igmp = {}
        out.igmp.type = igmp.igmp_type_name
        out.igmp.group_address = igmp.group_address
        out.igmp.response_length = igmp.length
        if igmp.sources then out.igmp.sources = igmp.sources end
    end
    if pim and pim.received then
        insert(protocols, "PIM")
        out.pim = {}
        out.pim.version = pim.pim_version
        out.pim.response_length = pim.length
    end
    if #protocols > 0 then
        out.status = "MULTICAST_ROUTING_ACTIVE"
        out.protocols_detected = protocols
    else
        out.status = "NO_MULTICAST"
        out.message = "No multicast routing activity detected"
    end
    return out
end
