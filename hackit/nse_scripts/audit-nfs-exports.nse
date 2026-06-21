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

description = [[Checks NFS export permissions and world-readable shares.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "audit"}

local function nfs_showmount(host, port)
    local socket = new_socket()
    socket:set_timeout(5000)
    local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local portmap_pkt = char(0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x86, 0xa0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x6e, 0x66, 0x73, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01)
        socket:send(portmap_pkt)
        local _, r = socket:receive_bytes(256)
        local mount_port = 2049
        if r and #r > 20 then
            mount_port = r:byte(23) * 256 + r:byte(24)
        end
        socket:close()
        local mount_sock = new_socket()
        mount_sock:set_timeout(5000)
        local s2, _ = mount_sock:connect(host, mount_port)
        if not s2 then mount_sock:close() return nil end
        local dump_pkt = char(0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x86, 0xa3, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        mount_sock:send(dump_pkt)
        local _, dump_resp = mount_sock:receive_bytes(4096)
        mount_sock:close()
        local result = nil
        if dump_resp and #dump_resp > 24 then
            result = {}
            result.response_received = true
            result.length = #dump_resp
            result.exports = {}
            local pos = 25
            while pos < #dump_resp - 3 do
                local entry_len = (dump_resp:byte(pos) or 0) * 256^3 + (dump_resp:byte(pos+1) or 0) * 256^2 + (dump_resp:byte(pos+2) or 0) * 256 + (dump_resp:byte(pos+3) or 0)
                if entry_len < 1 or pos + 4 + entry_len > #dump_resp then break end
                local export = dump_resp:sub(pos + 4, pos + 4 + entry_len - 1):gsub("%z", "")
                if #export > 0 then
                    result.exports[#result.exports + 1] = export
                end
                pos = pos + 4 + entry_len
            end
        end
        return result
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return result
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 2049 or port.number == 111) end

action = function(host, port)
    local out = output_table()
    out.service = "NFS Export Audit"
    out.target = host.ip
    out.port = port.number
    local result = nfs_showmount(host, port)
    if result and result.response_received then
        out.response_length = result.length
        if #result.exports > 0 then
            out.status = "EXPORTS_ACCESSIBLE"
            out.risk = "HIGH"
            out.exports = result.exports
            out.export_count = #result.exports
            local world_readable = {}
            for _, e in ipairs(result.exports) do
                if e:find("*") or e:find("everyone") or e:find("world") then
                    insert(world_readable, e)
                end
            end
            if #world_readable > 0 then
                out.world_readable_exports = world_readable
                out.risk = "CRITICAL"
            end
        else
            out.status = "NO_EXPORTS"
            out.message = "No accessible NFS exports"
        end
    else
        out.status = "NO_RESPONSE"
        out.message = "No NFS export information available"
    end
    return out
end
