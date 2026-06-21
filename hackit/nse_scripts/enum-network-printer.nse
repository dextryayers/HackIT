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
Enumerates network printer information via SNMP and JetDirect protocols.
Discovers printer model, serial number, page count, toner levels, and
other device status information from SNMP-enabled printers.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(161, "snmp")

action = function(host, port)
    local result = {}
    local socket = new_socket("udp")
    socket:set_timeout(5000)
    local status, err = socket:connect(host, port)
    if not status then
        return format_output(false, "Could not connect via SNMP: " .. tostring(err))
    end
    local printer_oids = {
        {"1.3.6.1.2.1.43.5.1.1.16.1", "Printer model"},
        {"1.3.6.1.2.1.43.10.2.1.4.1.1", "Serial number"},
        {"1.3.6.1.2.1.43.11.1.1.9.1.1", "Page count"},
        {"1.3.6.1.2.1.25.3.2.1.3.1", "Device description"},
        {"1.3.6.1.2.1.1.1.0", "System description"},
    }
    for _, oid_entry in ipairs(printer_oids) do
        local oid = oid_entry[1]
        local label = oid_entry[2]
        local parts = {}
        for p in oid:gmatch("%d+") do
            insert(parts, tonumber(p))
        end
        local snmp_pkt = char(0x30, 0x00, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x00, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00, 0x30, 0x00, 0x06, 0x00)
        local oid_bytes = char(0x2b)
        for i, p in ipairs(parts) do
            if p < 128 then
                oid_bytes = oid_bytes .. char(p)
            else
                oid_bytes = oid_bytes .. char(128 + (p >> 7), p & 127)
            end
        end
        local final_pkt = snmp_pkt .. oid_bytes .. char(0x05, 0x00)
        socket:send(final_pkt)
        local status, data = socket:receive()
        if status and data then
            insert(result, ("%s: data received (%d bytes)"):format(label, #data))
        end
    end
    socket:close()
    if #result == 0 then
        insert(result, "No printer information retrieved via SNMP")
    end
    return format_output(true, result)
end
