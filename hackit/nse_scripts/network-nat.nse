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
local new_socket = nmap.new_socket
local resolve = nmap.resolve

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

description = [[Detects NAT by comparing TTL values and IP ID sequences.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local out = output_table()
    out.service = "NAT Detection"
    out.target = host.ip
    out.port = port.number
    local nat_indicators = {}
    if host.os and host.os_tbl and host.os_tbl.ip_id_seq then
        local seq = host.os_tbl.ip_id_seq
        out.ip_id_sequence = seq
        if seq == "ZERO" or seq == "INCREMENTAL" or seq == "BROKEN" then
            insert(nat_indicators, "IP ID sequence '" .. seq .. "' suggests NAT")
        end
    end
    if host.times and host.times.ttl then
        out.ttl = host.times.ttl
        if host.times.ttl > 0 and host.times.ttl < 64 then
            insert(nat_indicators, "TTL " .. host.times.ttl .. " (<64) — likely behind NAT")
        elseif host.times.ttl >= 64 and host.times.ttl < 128 then
            insert(nat_indicators, "TTL " .. host.times.ttl .. " — may be behind 1-layer NAT")
        end
    end
    local socket = new_socket()
    socket:set_timeout(3000)
    local ok, resp = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local initial = socket:get_status()
        socket:close()
        return initial
    end)
    if not ok then pcall(socket.close, socket) end
    if host.os and host.os_tbl and host.os_tbl.distance then
        out.hop_distance = host.os_tbl.distance
        if host.os_tbl.distance > 1 then
            insert(nat_indicators, "Hop distance " .. host.os_tbl.distance .. " suggests NAT/router")
        end
    end
    if #nat_indicators > 0 then
        out.nat_detected = true
        out.indicators = nat_indicators
    else
        out.nat_detected = false
        out.message = "No NAT signs detected"
    end
    return out
end
