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

description = [[
Enumerates NFS export lists by connecting to the NFS portmapper and
making MOUNT protocol requests. Lists available NFS shares including
export paths, access permissions, and client restrictions.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(2049, "nfs")

local function rpc_packet(prog, vers, proc)
    local xid = 0
    local msg_type = 0
    local rpcvers = 2
    local auth = char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    local packet = char(
        xid >> 24, (xid >> 16) & 0xff, (xid >> 8) & 0xff, xid & 0xff,
        msg_type >> 24, (msg_type >> 16) & 0xff, (msg_type >> 8) & 0xff, msg_type & 0xff,
        rpcvers >> 24, (rpcvers >> 16) & 0xff, (rpcvers >> 8) & 0xff, rpcvers & 0xff,
        prog >> 24, (prog >> 16) & 0xff, (prog >> 8) & 0xff, prog & 0xff,
        vers >> 24, (vers >> 16) & 0xff, (vers >> 8) & 0xff, vers & 0xff,
        proc >> 24, (proc >> 16) & 0xff, (proc >> 8) & 0xff, proc & 0xff
    ) .. auth .. auth
    return packet
end

local function mount_export_packet()
    return rpc_packet(100005, 3, 5)
end

local function rpc_null_packet()
    return rpc_packet(100000, 4, 0)
end

action = function(host, port)
    local result = {}
    local socket = new_socket()
    socket:set_timeout(5000)
    local status, err = socket:connect(host, port)
    if not status then
        return format_output(false, "Could not connect: " .. tostring(err))
    end
    socket:send(rpc_null_packet())
    local status, response = socket:receive_bytes(1)
    if status then
        insert(result, "NFS portmapper responding")
        socket:send(mount_export_packet())
        local status, export_resp = socket:receive_bytes(1)
        if status and export_resp then
            insert(result, ("NFS MOUNT export response received (%d bytes)"):format(#export_resp))
            for export in gmatch(export_resp, "([%w/_-]+)") do
                if match(export, "^/") then
                    insert(result, ("Export: %s"):format(export))
                end
            end
        end
    end
    socket:close()
    if #result == 1 then
        insert(result, "No NFS exports enumerated (access may be restricted)")
    end
    return format_output(true, result)
end
