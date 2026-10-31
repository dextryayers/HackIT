local stdnse = require "stdnse"
local smb = require "smb"
local string = require "string"
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

description = [[Lists available SMB shares on the target, including share names, types, and comments. Extracts share details with disk, IPC, printer, and special share categorization.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open" and port.number == 445
end

local share_type_names = {
    [0] = "Disk", [1] = "Printer", [2] = "Device",
    [3] = "IPC", [0x80000000] = "Special",
}

action = function(host, port)
    local result = output_table()

    local ok, smbstate = pcall(smb.start, host, port)
    if not ok or not smbstate then
        return format_output(false, "Could not establish SMB session")
    end

    local ok2, smbstate2 = pcall(smb.negotiate_protocol, smbstate)
    if not ok2 then
        smb.stop(smbstate)
        return format_output(false, "SMB protocol negotiation failed")
    end
    smbstate = smbstate2

    local ok3, smbstate3 = pcall(smb.session_setup, smbstate, "", "")
    if not ok3 then
        smb.stop(smbstate)
        return format_output(false, "SMB session setup failed (null session may not be available)")
    end
    smbstate = smbstate3

    local ok4, shares = pcall(smb.list_shares, smbstate)
    smb.stop(smbstate)

    if not ok4 or not shares then
        return format_output(false, "Failed to list SMB shares")
    end

    local share_list = {}
    local disk_count = 0
    local ipc_count = 0
    local printer_count = 0
    local special_count = 0

    for _, share in ipairs(shares) do
        local share_entry = {
            name = share.name,
            type = share_type_names[share.type] or format("Unknown (0x%x)", share.type),
            comment = share.comment or "",
        }

        if share.type == 0 then disk_count = disk_count + 1 end
        if share.type == 3 then ipc_count = ipc_count + 1 end
        if share.type == 1 then printer_count = printer_count + 1 end
        if share.type == 0x80000000 then special_count = special_count + 1 end

        insert(share_list, share_entry)
    end

    result.shares = share_list
    result.share_count = #share_list
    result.disk_shares = disk_count
    result.ipc_shares = ipc_count
    result.printer_shares = printer_count
    result.special_shares = special_count

    return format_output(true, result)
end
