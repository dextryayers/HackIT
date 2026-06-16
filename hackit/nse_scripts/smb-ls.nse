local stdnse = require "stdnse"
local smb = require "smb"
local string = require "string"

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

    local ok3, smbstate3 = pcall(smb.session_setup, smbstate, "", "")
    if not ok3 then
        smb.stop(smbstate)
        return stdnse.format_output(false, "SMB session setup failed (null session may not be available)")
    end
    smbstate = smbstate3

    local ok4, shares = pcall(smb.list_shares, smbstate)
    smb.stop(smbstate)

    if not ok4 or not shares then
        return stdnse.format_output(false, "Failed to list SMB shares")
    end

    local share_list = {}
    local disk_count = 0
    local ipc_count = 0
    local printer_count = 0
    local special_count = 0

    for _, share in ipairs(shares) do
        local share_entry = {
            name = share.name,
            type = share_type_names[share.type] or string.format("Unknown (0x%x)", share.type),
            comment = share.comment or "",
        }

        if share.type == 0 then disk_count = disk_count + 1 end
        if share.type == 3 then ipc_count = ipc_count + 1 end
        if share.type == 1 then printer_count = printer_count + 1 end
        if share.type == 0x80000000 then special_count = special_count + 1 end

        table.insert(share_list, share_entry)
    end

    result.shares = share_list
    result.share_count = #share_list
    result.disk_shares = disk_count
    result.ipc_shares = ipc_count
    result.printer_shares = printer_count
    result.special_shares = special_count

    return stdnse.format_output(true, result)
end
