local stdnse = require "stdnse"
local smb = require "smb"
local string = require "string"
local bit = require "bit"

description = [[Checks the SMB security mode of the target, including user vs share-level security, signing requirements, and encryption support.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open" and port.number == 445
end

action = function(host, port)
    local result = stdnse.output_table()

    local ok, smbstate = pcall(smb.start, host, port)
    if not ok or not smbstate then
        return stdnse.format_output(false, "Could not establish SMB session")
    end

    local ok2, smbstate2 = pcall(smb.negotiate_protocol, smbstate)
    if not ok2 then
        smb.stop(smbstate)
        return stdnse.format_output(false, "SMB protocol negotiation failed")
    end
    smbstate = smbstate2

    local sec_mode = smbstate.security_mode or 0
    local sec_details = {}

    if bit.band(sec_mode, 1) == 1 then
        result.security_level = "User-level"
        table.insert(sec_details, "User-level security (requires authentication)")
    else
        result.security_level = "Share-level"
        table.insert(sec_details, "Share-level security (password per share)")
    end

    if bit.band(sec_mode, 2) == 2 then
        result.signing_enabled = true
        table.insert(sec_details, "SMB signing enabled")
    else
        result.signing_enabled = false
        table.insert(sec_details, "SMB signing disabled")
    end

    if bit.band(sec_mode, 4) == 4 then
        result.signing_required = true
        table.insert(sec_details, "SMB signing required")
    else
        result.signing_required = false
        table.insert(sec_details, "SMB signing not required")
    end

    if bit.band(sec_mode, 8) == 8 then
        result.encryption_required = true
        table.insert(sec_details, "SMB encryption required")
    end

    result.security_details = sec_details
    result.raw_security_mode = string.format("0x%02x", sec_mode)

    if smbstate.key_length then
        result.session_key_length = smbstate.key_length
    end

    smb.stop(smbstate)

    return stdnse.format_output(true, result)
end
