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

description = [[Checks for rlogin/rsh trust relationships (.rhosts) allowing unauthorized access.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "audit"}

local trust_users = {"root", "nobody", "guest", "test", "admin", "user"}
local trust_from = {"localhost", "127.0.0.1", "trusted.host.com"}

local function rlogin_connect(host, port, remote_user, local_user, terminal)
    remote_user = remote_user or "root"
    local_user = local_user or "root"
    terminal = terminal or "xterm"
    local socket = new_socket()
    socket:set_timeout(5000)
    local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local null = char(0)
        local pkt = null .. remote_user .. null .. local_user .. null .. terminal .. null
        socket:send(pkt)
        local _, resp = socket:receive_bytes(256)
        socket:close()
        local result = nil
        if resp then
            result = {}
            result.response_received = true
            result.length = #resp
            result.remote_user = remote_user
            result.local_user = local_user
            if byte(resp, 1) == 0 then
                result.auth_status = "TRUSTED"
                result.trust_relationship = true
            elseif find(resp, "Password") or find(resp, "password") then
                result.auth_status = "PASSWORD_REQUIRED"
                result.trust_relationship = false
            elseif find(resp, "denied") or find(resp, "refused") or find(resp, "sorry") then
                result.auth_status = "DENIED"
                result.trust_relationship = false
            elseif find(resp, "#") or find(resp, "$") or find(resp, ">") then
                result.auth_status = "TRUSTED_SHELL"
                result.trust_relationship = true
            else
                result.auth_status = "UNKNOWN"
                result.raw_prefix = sub(resp, 1, 20):gsub("[\r\n]", " ")
            end
        end
        return result
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return result
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 513 or port.number == 514) end

action = function(host, port)
    local out = output_table()
    out.service = "rlogin/rsh Audit"
    out.target = host.ip
    out.port = port.number
    local trust_found = false
    local results = {}
    for _, ru in ipairs(trust_users) do
        for _, lu in ipairs(trust_from) do
            local ok, r = pcall(rlogin_connect, host, port, ru, lu)
            if ok and r and r.response_received then
                insert(results, r)
                if r.trust_relationship then
                    trust_found = true
                end
            end
        end
    end
    out.probes = results
    if trust_found then
        out.status = "TRUST_RELATIONSHIPS_DETECTED"
        out.risk = "CRITICAL"
        out.message = "rlogin/rsh has trust relationships (no password prompt)"
    else
        out.status = "NO_TRUST"
        out.risk = "LOW"
        out.message = "rlogin requires password or authentication configured"
    end
    return out
end
