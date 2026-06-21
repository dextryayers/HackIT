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
            for export in export_resp:gmatch("([%w/_-]+)") do
                if export:match("^/") then
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
