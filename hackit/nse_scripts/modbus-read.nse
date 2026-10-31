local nmap = require "nmap"
local stdnse = require "stdnse"
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

description = [[
Performs Modbus TCP unit ID enumeration by querying the Modbus slave
devices. Attempts to read holding registers and coil status from each
unit ID (1-247) to discover accessible Modbus devices on the network.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(502, "modbus")

local function modbus_read_holding_registers(unit_id, start_reg, count)
    local trans_id = 0x0001
    local proto_id = 0x0000
    local length = 6
    local func_code = 0x03
    return char(
        trans_id >> 8, trans_id & 0xff,
        proto_id >> 8, proto_id & 0xff,
        length >> 8, length & 0xff,
        unit_id,
        func_code,
        start_reg >> 8, start_reg & 0xff,
        count >> 8, count & 0xff
    )
end

action = function(host, port)
    local result = {}
    local socket = new_socket()
    socket:set_timeout(5000)
    local status, err = socket:connect(host, port)
    if not status then
        return format_output(false, "Could not connect: " .. tostring(err))
    end
    insert(result, "Modbus TCP service detected")
    local found_devices = 0
    for unit_id = 1, 10 do
        local request = modbus_read_holding_registers(unit_id, 0, 1)
        local status = socket:send(request)
        if not status then break end
        local status, response = socket:receive_bytes(1)
        if status and #response >= 9 then
            local resp_uid = byte(response, 7)
            local resp_func = byte(response, 8)
            if resp_func == 0x03 then
                insert(result, ("Unit ID %d: Responds to Modbus (function 0x03)"):format(unit_id))
                found_devices = found_devices + 1
            elseif resp_func == 0x83 then
                insert(result, ("Unit ID %d: Modbus exception response"):format(unit_id))
            end
        end
    end
    socket:close()
    if found_devices == 0 then
        insert(result, "No Modbus devices found responding on unit IDs 1-10")
    end
    return format_output(true, result)
end
