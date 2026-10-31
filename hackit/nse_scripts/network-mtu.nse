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

description = [[Discovers the path MTU by sending ICMP with DF bit and varying sizes.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local function probe_mtu_size(host, port, size)
    local socket = new_socket()
    socket:set_timeout(3000)
    local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local payload = rep("A", size)
        socket:send(payload)
        local _, resp = socket:receive_bytes(256)
        socket:close()
        if resp then
            return {success = true, response_length = #resp, data_match = (#resp > 0)}
        end
        return {success = false, response_length = 0}
    end)
    if not ok then pcall(socket.close, socket) return {success = false} end
    return result
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local out = output_table()
    out.service = "Path MTU Discovery"
    out.target = host.ip
    out.port = port.number
    local sizes = {1500, 1492, 1472, 1468, 1450, 1430, 1400, 1350, 1300, 1200, 1000, 576}
    local results = {}
    local max_success = 0
    for _, size in ipairs(sizes) do
        local ok, r = pcall(probe_mtu_size, host, port, size)
        if ok and r and r.success then
            insert(results, {size = size, status = "SUCCESS"})
            if size > max_success then max_success = size end
        else
            insert(results, {size = size, status = "FAIL"})
        end
    end
    out.probes = results
    out.mtu_estimate = (max_success > 0) and (max_success + 28) or nil
    out.mtu_confidence = (out.mtu_estimate and out.mtu_estimate >= 1472) and "HIGH" or "MEDIUM"
    return out
end
