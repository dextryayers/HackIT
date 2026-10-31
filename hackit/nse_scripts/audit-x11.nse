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

description = [[Checks if X11 server allows open access (no authentication).]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "audit"}

local function probe_x11_auth(host, port)
    local socket = new_socket()
    socket:set_timeout(5000)
    local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local conn_req = char(0x6c, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        socket:send(conn_req)
        local _, resp = socket:receive_bytes(128)
        socket:close()
        local result = nil
        if resp and #resp >= 8 then
            result = {}
            result.response_received = true
            result.length = #resp
            result.success_byte = byte(resp, 1)
            result.protocol_major = byte(resp, 3) or 0
            result.protocol_minor = byte(resp, 5) or 0
            if byte(resp, 1) == 1 then
                result.auth_required = false
                result.open_access = true
                if #resp >= 8 then
                    result.vendor = sub(resp, 7, 8)
                end
            elseif byte(resp, 1) == 0 then
                result.auth_required = true
                result.open_access = false
                result.reason_length = (byte(resp, 7) or 0) * 256 + (byte(resp, 8) or 0)
                if result.reason_length > 0 and #resp >= 8 + result.reason_length then
                    result.reason = sub(resp, 9, 8 + result.reason_length)
                end
            end
        end
        return result
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return result
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.number >= 6000 and port.number <= 6063 end

action = function(host, port)
    local out = output_table()
    out.service = "X11 Access Audit"
    out.target = host.ip
    out.display = ":" .. (port.number - 6000)
    out.port = port.number
    local result = probe_x11_auth(host, port)
    if result and result.response_received then
        out.protocol_version = result.protocol_major .. "." .. result.protocol_minor
        if result.open_access then
            out.status = "OPEN_ACCESS"
            out.risk = "CRITICAL"
            out.message = "X11 server is open (no auth required)"
        else
            out.status = "AUTH_REQUIRED"
            out.risk = "LOW"
            out.message = "X11 requires authentication"
            if result.reason then out.auth_reason = result.reason end
        end
    else
        out.status = "NO_RESPONSE"
        out.message = "X11 did not respond to connection request"
    end
    return out
end
