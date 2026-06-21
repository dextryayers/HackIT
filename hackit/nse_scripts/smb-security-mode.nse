local stdnse = require "stdnse"
local smb = require "smb"
local string = require "string"
local bit = require "bit"
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

description = [[Checks the SMB security mode of the target, including user vs share-level security, signing requirements, and encryption support.]]
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

    local sec_mode = smbstate.security_mode or 0
    local sec_details = {}

    if bit.band(sec_mode, 1) == 1 then
        result.security_level = "User-level"
        insert(sec_details, "User-level security (requires authentication)")
    else
        result.security_level = "Share-level"
        insert(sec_details, "Share-level security (password per share)")
    end

    if bit.band(sec_mode, 2) == 2 then
        result.signing_enabled = true
        insert(sec_details, "SMB signing enabled")
    else
        result.signing_enabled = false
        insert(sec_details, "SMB signing disabled")
    end

    if bit.band(sec_mode, 4) == 4 then
        result.signing_required = true
        insert(sec_details, "SMB signing required")
    else
        result.signing_required = false
        insert(sec_details, "SMB signing not required")
    end

    if bit.band(sec_mode, 8) == 8 then
        result.encryption_required = true
        insert(sec_details, "SMB encryption required")
    end

    result.security_details = sec_details
    result.raw_security_mode = format("0x%02x", sec_mode)

    if smbstate.key_length then
        result.session_key_length = smbstate.key_length
    end

    smb.stop(smbstate)

    return format_output(true, result)
end
