local stdnse = require "stdnse"
local smb = require "smb"
local string = require "string"
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

description = [[Detects Windows OS version via SMB protocol negotiation. Extracts OS name, LAN Manager version, domain/workgroup, native OS, and SMB dialect information.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open" and port.number == 445
end

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

    if smbstate.os then
        result.operating_system = smbstate.os
        if smbstate.os:match("Windows") then
            result.os_family = "Windows"
            local versions = {
                ["10.0"] = "Windows 10/Server 2016/2019/2022",
                ["6.3"] = "Windows 8.1/Server 2012 R2",
                ["6.2"] = "Windows 8/Server 2012",
                ["6.1"] = "Windows 7/Server 2008 R2",
                ["6.0"] = "Windows Vista/Server 2008",
                ["5.2"] = "Windows XP x64/Server 2003",
                ["5.1"] = "Windows XP",
                ["5.0"] = "Windows 2000",
            }
            for ver, name in pairs(versions) do
                if smbstate.os:find(ver) then
                    result.os_version_hint = name
                    break
                end
            end
        elseif smbstate.os:match("Unix") or smbstate.os:match("Linux") or smbstate.os:match("Samba") then
            result.os_family = "Unix/Linux (Samba)"
        end
    end

    if smbstate.lanman then
        result.lan_manager_version = smbstate.lanman
    end

    if smbstate.domain then
        result.domain_or_workgroup = smbstate.domain
    end

    if smbstate.native_os then
        result.native_os = smbstate.native_os
    end

    if smbstate.native_lm then
        result.native_lan_manager = smbstate.native_lm
    end

    if smbstate.dialect then
        result.smb_dialect = smbstate.dialect
    end

    if smbstate.max_xmit then
        result.max_buffer_size = smbstate.max_xmit
    end

    if smbstate.session_key then
        result.session_key_present = true
    end

    if smbstate.server_guid then
        result.server_guid = smbstate.server_guid
    end

    smb.stop(smbstate)

    if next(result) then
        return format_output(true, result)
    end

    return format_output(false, "No OS information retrieved")
end
