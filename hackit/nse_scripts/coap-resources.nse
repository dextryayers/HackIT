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
Discovers resources on CoAP (Constrained Application Protocol) services by
sending .well-known/core discovery requests. Enumerates available resource
paths, resource types, and interface descriptions from CoAP servers.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(5683, "coap")

local function coap_discover()
    local version = 1
    local ttype = 0
    local tkl = 0
    local code = 1
    local msgid = 1
    local token = ""
    local options = ""
    local payload = ""
    local ver_type_tkl = char((version << 6) | (ttype << 4) | tkl)
    local first_byte = char(byte(ver_type_tkl, 1), code)
    local packet = first_byte .. char(0x00, msgid) .. token .. options .. payload
    return packet
end

action = function(host, port)
    local result = {}
    local socket = new_socket("udp")
    socket:set_timeout(5000)
    local status, err = socket:connect(host, port)
    if not status then
        return format_output(false, "Could not connect: " .. tostring(err))
    end
    local discover = coap_discover()
    status, err = socket:send(discover)
    if not status then
        socket:close()
        return format_output(false, "Could not send CoAP discovery: " .. tostring(err))
    end
    local status, response = socket:receive_bytes(1)
    if not status then
        socket:close()
        return format_output(false, "No CoAP response received")
    end
    if #response >= 4 then
        local code_val = byte(response, 3)
        local code_class = code_val >> 5
        local code_detail = code_val & 0x1f
        insert(result, ("CoAP response code: %d.%02d"):format(code_class, code_detail))
        if code_val == 0x45 then
            insert(result, "CoAP 2.05 Content received")
        end
        local payload_start = 0
        for i = 1, #response do
            if byte(response, i) == 0xff then
                payload_start = i + 1
                break
            end
        end
        if payload_start > 0 then
            local payload = sub(response, payload_start)
            if payload ~= "" then
                for resource in gmatch(payload, "</?([^>]+)>") do
                    insert(result, ("Resource: %s"):format(resource))
                end
            end
        end
    end
    socket:close()
    return format_output(true, result)
end
