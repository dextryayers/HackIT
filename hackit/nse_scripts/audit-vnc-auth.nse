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
local msleep = function(ms)
    if stdnse and stdnse.sleep then
        return stdnse.sleep((ms or 0) / 1000)
    end
    if nmap.msleep then
        return nmap.msleep(ms or 0)
    end
    local deadline = nmap.clock() + (ms or 0) / 1000
    while nmap.clock() < deadline do end
    return true
end
local new_socket = nmap.new_socket
local resolve = nmap.resolve

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    if stdnse and stdnse.sleep then
        return stdnse.sleep(seconds)
    end
    if nmap.msleep then
        return nmap.msleep(math.max(0, math.floor((seconds or 0) * 1000)))
    end
    local deadline = nmap.clock() + (seconds or 0)
    while nmap.clock() < deadline do end
    return true
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

description = [[Checks if VNC authentication is enabled.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "audit"}

local auth_type_names = {
    [0] = "Invalid",
    [1] = "None (No Auth)",
    [2] = "VNC Authentication (Standard)",
    [5] = "RA2 (RA2ne)",
    [6] = "RA2ne",
    [16] = "Tight",
    [17] = "Ultra",
    [18] = "TLS",
    [19] = "VeNCrypt",
    [20] = "GTK-VNC SASL",
    [21] = "MD5 Hash",
    [22] = "Colin Dean x",
    [30] = "Apple Remote Desktop",
}

local function vnc_handshake(host, port)
    local socket = new_socket()
    socket:set_timeout(5000)
    local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local _, banner = socket:receive_bytes(12)
        local result = nil
        if banner and #banner >= 12 then
            result = {}
            result.response_received = true
            result.length = #banner
            result.protocol_version = sub(banner, 0, 11):gsub("[\r\n]", "")
            local auth_count = byte(banner, 12) or 0
            result.auth_schemes = {}
            result.auth_count = auth_count
            local pos = 13
            for i = 1, auth_count do
                if pos > #banner then break end
                local auth_type = byte(banner, pos) or 0
                result.auth_schemes[#result.auth_schemes + 1] = {
                    code = auth_type,
                    name = auth_type_names[auth_type] or ("Unknown (" .. auth_type .. ")")
                }
                pos = pos + 1
            end
        end
        socket:close()
        return result
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return result
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 5900 or port.number == 5901 or port.number == 5800) end

action = function(host, port)
    local out = output_table()
    out.service = "VNC Authentication Audit"
    out.target = host.ip
    out.port = port.number
    local result = vnc_handshake(host, port)
    if result and result.response_received then
        out.protocol_version = result.protocol_version
        out.auth_scheme_count = result.auth_count
        out.auth_schemes = result.auth_schemes
        local has_none = false
        local has_vnc = false
        for _, s in ipairs(result.auth_schemes) do
            if s.code == 1 then has_none = true end
            if s.code == 2 then has_vnc = true end
        end
        if has_none then
            out.status = "NO_AUTH_REQUIRED"
            out.risk = "CRITICAL"
            out.message = "VNC: No authentication required (insecure)"
        elseif has_vnc then
            out.status = "VNC_AUTH_REQUIRED"
            out.risk = "LOW"
            out.message = "VNC: Standard VNC authentication required"
        else
            out.status = "ALTERNATE_AUTH"
            out.risk = "MEDIUM"
            out.message = "VNC: Non-standard authentication in use"
        end
    else
        out.status = "NO_RESPONSE"
        out.message = "Could not determine VNC auth status"
    end
    return out
end
