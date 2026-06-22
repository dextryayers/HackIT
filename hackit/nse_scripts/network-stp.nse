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

description = [[Detects Spanning Tree Protocol (STP) by looking for BPDU frames.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local function capture_bpdu_frame(timeout)
    timeout = timeout or 5000
    local socket = new_socket("raw")
    socket:set_timeout(timeout)
    local ok, resp = pcall(function()
        local dst = char(0x01, 0x80, 0xc2, 0x00, 0x00, 0x00)
        local src = char(0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
        local pkt = dst .. src .. char(0x00, 0x26)
        pkt = pkt .. char(0x42, 0x42, 0x03, 0x00, 0x00, 0x00)
        socket:send(pkt)
        local _, r = socket:receive_bytes(256)
        socket:close()
        local result = nil
        if r and #r >= 35 then
            result = {}
            result.received = true
            result.length = #r
            result.bpdu_type = (byte(r, 20) == 0x00) and "Configuration BPDU" or "TCN BPDU"
            if #r >= 22 then
                local root_id = ""
                for i = 23, 30 do root_id = root_id .. format("%02x", byte(r, i)) end
                result.root_bridge_id = root_id
            end
            if #r >= 36 then
                result.root_path_cost = byte(r, 36)
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
    out.service = "STP Detection"
    out.target = host.ip
    local frame = capture_bpdu_frame(5000)
    if frame and frame.received then
        out.status = "STP_DETECTED"
        out.stp_active = true
        out.bpdu_length = frame.length
        out.bpdu_type = frame.bpdu_type
        if frame.root_bridge_id then out.root_bridge_id = frame.root_bridge_id end
        if frame.root_path_cost then out.root_path_cost = frame.root_path_cost end
    else
        out.status = "NO_STP"
        out.stp_active = false
        out.message = "No STP BPDU frames detected"
    end
    return out
end
