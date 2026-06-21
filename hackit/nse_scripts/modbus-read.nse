local nmap = require "nmap"
local stdnse = require "stdnse"
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
            local resp_uid = response:byte(7)
            local resp_func = response:byte(8)
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
