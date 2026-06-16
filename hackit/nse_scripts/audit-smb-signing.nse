local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Checks if SMB signing is required on the target by analyzing SMB negotiation response.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "audit"}

local function negotiate_smb(host, port, smb_version)
    smb_version = smb_version or "v1"
    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local nbss
        local neg_pkt
        if smb_version == "v1" then
            nbss = string.char(0x00, 0x00, 0x00, 0x45)
            neg_pkt = string.char(0xfe, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
            neg_pkt = neg_pkt .. string.char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        else
            nbss = string.char(0x00, 0x00, 0x00, 0x90)
            neg_pkt = string.char(0xfe, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
            neg_pkt = neg_pkt .. string.char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
            neg_pkt = neg_pkt .. string.rep(string.char(0x00), 110)
        end
        socket:send(nbss .. neg_pkt)
        local _, resp = socket:receive_bytes(256)
        socket:close()
        if resp then
            local result = {}
            result.protocol = smb_version
            result.negotiated = true
            local signing_byte = resp:sub(47, 47)
            local byte_val = string.byte(signing_byte or "\x00")
            result.security_mode_byte = byte_val
            if byte_val then
                result.signing_enabled = (byte_val & 0x01 == 0x01)
                result.signing_required = (byte_val & 0x02 == 0x02)
            end
            if #resp >= 40 then
                local dialects = {}
                for i = 40, #resp - 1 do
                    local d = resp:sub(i, i+1)
                    if d == "\x02\x02" then dialects[#dialects + 1] = "SMB 2.0.2" end
                    if d == "\x02\x10" then dialects[#dialects + 1] = "SMB 2.1" end
                    if d == "\x03\x00" then dialects[#dialects + 1] = "SMB 3.0" end
                    if d == "\x03\x02" then dialects[#dialects + 1] = "SMB 3.0.2" end
                    if d == "\x03\x11" then dialects[#dialects + 1] = "SMB 3.1.1" end
                end
                if #dialects > 0 then result.negotiated_dialects = dialects end
            end
            return result
        end
        return nil
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return result
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 139 or port.number == 445) end

action = function(host, port)
    local out = stdnse.output_table()
    out.service = "SMB Signing Audit"
    out.target = host.ip
    out.port = port.number
    local result = negotiate_smb(host, port, "v1")
    if result then
        out.protocol_negotiated = result.protocol
        out.security_mode_byte = result.security_mode_byte
        out.signing_enabled = result.signing_enabled
        out.signing_required = result.signing_required
        if result.negotiated_dialects then
            out.negotiated_dialects = result.negotiated_dialects
        end
        if result.signing_required then
            out.status = "SMB_SIGNING_REQUIRED"
            out.risk = "LOW"
            out.message = "SMB signing is required on this host"
        else
            out.status = result.signing_enabled and "SMB_SIGNING_ENABLED_NOT_REQUIRED" or "SMB_SIGNING_DISABLED"
            out.risk = result.signing_enabled and "MEDIUM" or "HIGH"
            out.message = result.signing_enabled and "SMB signing enabled but not required" or "SMB signing is not required or disabled"
        end
    else
        out.status = "NO_RESPONSE"
        out.message = "Could not determine SMB signing status"
    end
    return out
end
