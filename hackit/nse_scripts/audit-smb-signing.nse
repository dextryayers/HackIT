local stdnse = require "stdnse"
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

description = [[Checks if SMB signing is required on the target by analyzing SMB negotiation response.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "audit"}

local function negotiate_smb(host, port, smb_version)
    smb_version = smb_version or "v1"
    local socket = new_socket()
    socket:set_timeout(5000)
    local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local nbss
        local neg_pkt
        if smb_version == "v1" then
            nbss = char(0x00, 0x00, 0x00, 0x45)
            neg_pkt = char(0xfe, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
            neg_pkt = neg_pkt .. char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        else
            nbss = char(0x00, 0x00, 0x00, 0x90)
            neg_pkt = char(0xfe, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
            neg_pkt = neg_pkt .. char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
            neg_pkt = neg_pkt .. rep(char(0x00), 110)
        end
        socket:send(nbss .. neg_pkt)
        local _, resp = socket:receive_bytes(256)
        socket:close()
        if resp then
            local result = {}
            result.protocol = smb_version
            result.negotiated = true
            local signing_byte = sub(resp, 47, 47)
            local byte_val = byte(signing_byte or "\x00")
            result.security_mode_byte = byte_val
            if byte_val then
                result.signing_enabled = (byte_val & 0x01 == 0x01)
                result.signing_required = (byte_val & 0x02 == 0x02)
            end
            if #resp >= 40 then
                local dialects = {}
                for i = 40, #resp - 1 do
                    local d = sub(resp, i, i+1)
                    if d == "\x02\x02" then insert(dialects, "SMB 2.0.2") end
                    if d == "\x02\x10" then insert(dialects, "SMB 2.1") end
                    if d == "\x03\x00" then insert(dialects, "SMB 3.0") end
                    if d == "\x03\x02" then insert(dialects, "SMB 3.0.2") end
                    if d == "\x03\x11" then insert(dialects, "SMB 3.1.1") end
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
    local out = output_table()
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
