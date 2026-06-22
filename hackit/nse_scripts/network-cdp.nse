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

description = [[Detects Cisco Discovery Protocol (CDP) frames on the network.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local function capture_cdp_frame(timeout)
    timeout = timeout or 5000
    local socket = new_socket("raw")
    socket:set_timeout(timeout)
    local ok, resp = pcall(function()
        local dst = char(0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc)
        local src = char(0x00, 0x00, 0x00, 0x00, 0x00, 0x02)
        local cdp_hdr = char(0x00, 0x00, 0x20, 0x00, 0x01)
        local pkt = dst .. src .. cdp_hdr
        socket:send(pkt)
        local _, r = socket:receive_bytes(512)
        socket:close()
        local result = nil
        if r and #r > 20 then
            result = {}
            result.received = true
            result.length = #r
            local pos = 15
            while pos < #r - 3 do
                local tlv_type = (byte(r, pos) or 0) * 256 + (byte(r, pos + 1) or 0)
                local tlv_len = (byte(r, pos + 2) or 0) * 256 + (byte(r, pos + 3) or 0)
                if tlv_len < 4 then break end
                local value = sub(r, pos + 4, pos + tlv_len - 1)
                if tlv_type == 1 then result.device_id = gsub(value, "[\r\n]", "") end
                if tlv_type == 4 then result.platform = gsub(value, "[\r\n]", "") end
                if tlv_type == 5 then result.capabilities = gsub(value, "[\r\n]", "") end
                pos = pos + tlv_len
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
    out.service = "CDP Detection"
    out.target = host.ip
    local frame = capture_cdp_frame(5000)
    if frame and frame.received then
        out.status = "CDP_DETECTED"
        out.cdp_active = true
        out.frame_length = frame.length
        if frame.device_id then out.device_id = frame.device_id end
        if frame.platform then out.platform = frame.platform end
        if frame.capabilities then out.capabilities = frame.capabilities end
    else
        out.status = "NO_CDP"
        out.cdp_active = false
        out.message = "No CDP frames detected"
    end
    return out
end
