local stdnse = require "stdnse"
local smb = require "smb"
local string = require "string"

description = [[Detects Windows OS version via SMB protocol negotiation. Extracts OS name, LAN Manager version, domain/workgroup, native OS, and SMB dialect information.]]
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
        return stdnse.format_output(true, result)
    end

    return stdnse.format_output(false, "No OS information retrieved")
end
