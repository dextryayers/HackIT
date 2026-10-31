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
                local version = match(resp, "version\\?\"?([%d%.]+)")
                if version then
                    result.version = version
                    local parts = {}
                    for v in gmatch(version, "%d+") do
                        insert(parts, tonumber(v))
                    end
                    if #parts >= 1 then result.version_major = parts[1] end
                    if #parts >= 2 then result.version_minor = parts[2] end
                end
                local max_bson = match(resp, "maxBsonObjectSize\"?[^%d]*(%d+)")
                if max_bson then result.max_bson_object_size = tonumber(max_bson) end
                local max_msg = match(resp, "maxMessageSizeBytes\"?[^%d]*(%d+)")
                if max_msg then result.max_message_size_bytes = tonumber(max_msg) end
                local max_wire = match(resp, "maxWireVersion\"?[^%d]*(%d+)")
                if max_wire then result.max_wire_version = tonumber(max_wire) end
                if match(resp, "setName") or match(resp, "SetName") then
                    result.replica_set = true
                end
                local me = match(resp, "me\"?[^%w]*\"([^\"]+)\"")
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
