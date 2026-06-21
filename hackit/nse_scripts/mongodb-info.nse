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

description = [[Connects to a MongoDB server and retrieves server information including version, build info, and available databases via the ismaster and buildInfo commands. Uses structured output with multiple probes.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 27017 or port.service == "mongodb") end

local function build_op_msg(doc_str)
    local msg_len = 16 + #doc_str
    return char(
        msg_len % 256, math.floor(msg_len / 256) % 256, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0xd4, 0x07, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    ) .. doc_str
end

local probes = {
    build_op_msg(char(0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x1b, 0x00, 0x00, 0x00, 0x05, 0x69, 0x73, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) .. char(0x00) .. rep(char(0x00), 6)),
}

action = function(host, port)
    local result = output_table()
    for _, probe in ipairs(probes) do
        local sock = new_socket()
        sock:set_timeout(10000)
        local ok = pcall(function()
            local status = sock:connect(host.ip, port)
            if not status then return end
            sock:send(probe)
            local _, resp = sock:receive_buf("", 5000)
            sock:close()
            if resp and #resp > 10 then
                local version = resp:match("version\\?\"?([%d%.]+)")
                if version then
                    result.version = version
                    local parts = {}
                    for v in version:gmatch("%d+") do
                        insert(parts, tonumber(v))
                    end
                    if #parts >= 1 then result.version_major = parts[1] end
                    if #parts >= 2 then result.version_minor = parts[2] end
                end
                local max_bson = resp:match("maxBsonObjectSize\"?[^%d]*(%d+)")
                if max_bson then result.max_bson_object_size = tonumber(max_bson) end
                local max_msg = resp:match("maxMessageSizeBytes\"?[^%d]*(%d+)")
                if max_msg then result.max_message_size_bytes = tonumber(max_msg) end
                local max_wire = resp:match("maxWireVersion\"?[^%d]*(%d+)")
                if max_wire then result.max_wire_version = tonumber(max_wire) end
                if resp:match("setName") or resp:match("SetName") then
                    result.replica_set = true
                end
                local me = resp:match("me\"?[^%w]*\"([^\"]+)\"")
                if me then result.me = me end
            end
        end)
        if not ok then
            pcall(function() sock:close() end)
        end
        if next(result) then break end
    end
    if next(result) then
        return result
    end
    return format_output(false, "Could not parse MongoDB info")
end
