local stdnse = require "stdnse"
local smb = require "smb"
local string = require "string"
-- Lua 5.4 has no "bit" module; this is a 32-bit compatible replacement.
local bit = (function()
    local floor = math.floor
    local function toint(x) return floor(x) & 0xFFFFFFFF end
    local function fold(fn, a, ...)
        local r = toint(a)
        for i = 1, select("#", ...) do
            r = toint(fn(r, select(i, ...)))
        end
        return r
    end
    return {
        band = function(...) return fold(function(x, y) return x & y end, ...) end,
        bor = function(...) return fold(function(x, y) return x | y end, ...) end,
        bxor = function(...) return fold(function(x, y) return x ~ y end, ...) end,
        bnot = function(x) return (~toint(x)) & 0xFFFFFFFF end,
        lshift = function(x, n) return (toint(x) << (n & 31)) & 0xFFFFFFFF end,
        rshift = function(x, n) return toint(x) >> (n & 31) end,
        arshift = function(x, n) return toint(x) >> (n & 31) end,
        tobit = function(x) return toint(x) end,
        tohex = function(x) return format("%08x", toint(x)) end,
    }
end)()
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
