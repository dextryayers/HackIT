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
local msleep = nmap.msleep

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    return nmap.msleep(math.max(0, math.floor(seconds * 1000)))
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
