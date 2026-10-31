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
            result.icmpv6_type = byte(r, 1)
            if byte(r, 1) == 0x88 then result.message_type = "Neighbor Advertisement (NA)" end
            if byte(r, 1) == 0x87 then result.message_type = "Neighbor Solicitation (NS)" end
            if byte(r, 1) == 0x86 then result.message_type = "Router Solicitation (RS)" end
            if byte(r, 1) == 0x85 then result.message_type = "Router Advertisement (RA)" end
            if #r >= 24 then
                local target_addr = ""
                for i = 9, 24 do target_addr = target_addr .. format("%02x", byte(r, i)) if i % 2 == 0 and i < 24 then target_addr = target_addr .. ":" end end
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
    out.ipv6_present = (host.ip and host.match(ip, ":")) ~= nil
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
