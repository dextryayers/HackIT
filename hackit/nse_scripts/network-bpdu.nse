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

description = [[Discovers BPDU (Bridge Protocol Data Unit) frames for STP topology.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local function listen_bpdu_frame(timeout)
    timeout = timeout or 5000
    local socket = new_socket("raw")
    socket:set_timeout(timeout)
    local ok, resp = pcall(function()
        local dst_mac = char(0x01, 0x80, 0xc2, 0x00, 0x00, 0x00)
        local src_mac = char(0x00, 0x00, 0x00, 0x00, 0x00, 0x04)
        local bpdu = dst_mac .. src_mac .. char(0x00, 0x26)
        bpdu = bpdu .. char(0x42, 0x42, 0x42, 0x42, 0x42, 0x42)
        socket:send(bpdu)
        local _, r = socket:receive_bytes(512)
        socket:close()
        local result = nil
        if r and #r >= 35 then
            result = {}
            result.received = true
            result.length = #r
            local flags_byte = r:byte(20) or 0
            if flags_byte == 0x00 then
                result.frame_type = "Configuration BPDU"
            elseif flags_byte == 0x80 then
                result.frame_type = "Topology Change Notification"
            else
                result.frame_type = "Unknown BPDU type (0x" .. format("%02x", flags_byte) .. ")"
            end
            if #r >= 22 then
                local root_id = ""
                for i = 23, 30 do root_id = root_id .. format("%02x", r:byte(i)) end
                result.root_bridge_id = root_id
            end
            if #r >= 36 then
                result.root_path_cost = r:byte(36)
            end
            if #r >= 31 then
                local bridge_id = ""
                for i = 31, 38 do bridge_id = bridge_id .. format("%02x", r:byte(i)) end
                result.bridge_id = bridge_id
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
    out.service = "BPDU Discovery"
    out.target = host.ip
    local frame = listen_bpdu_frame(5000)
    if frame and frame.received then
        out.status = "BPDU_DETECTED"
        out.bpdu_active = true
        out.frame_length = frame.length
        out.frame_type = frame.frame_type
        if frame.root_bridge_id then out.root_bridge_id = frame.root_bridge_id end
        if frame.root_path_cost then out.root_path_cost = frame.root_path_cost end
        if frame.bridge_id then out.bridge_id = frame.bridge_id end
    else
        out.status = "NO_BPDU"
        out.bpdu_active = false
        out.message = "No BPDU frames detected"
    end
    return out
end
