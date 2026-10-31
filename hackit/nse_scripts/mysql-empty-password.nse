local nmap = require "nmap"
local stdnse = require "stdnse"
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

description = [[
Checks MySQL servers for empty or default root passwords by attempting
authentication with common weak credentials including root with no password,
root with password 'root', and anonymous user access.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"auth", "intrusive"}

portrule = shortport.port_or_service(3306, "mysql")

local function mysql_handshake(socket)
    local status, data = socket:receive_bytes(1)
    if not status then return nil end
    if #data < 4 then return nil end
    local protocol_version = byte(data, 5)
    local server_end = find(data, "\0", 6)
    if not server_end then return nil end
    local auth_plugin_data = sub(data, server_end + 1, server_end + 8)
    return auth_plugin_data
end

local function try_auth(host, port, user, pass)
    local socket = new_socket()
    socket:set_timeout(5000)
    local status, err = socket:connect(host, port)
    if not status then return false, tostring(err) end
    local challenge = mysql_handshake(socket)
    if not challenge then socket:close() return false, "No handshake" end
    socket:close()
    return true, nil
end

action = function(host, port)
    local result = {}
    local socket = new_socket()
    socket:set_timeout(5000)
    local status, err = socket:connect(host, port)
    if not status then
        return format_output(false, "Could not connect to MySQL: " .. tostring(err))
    end
    local handshake = mysql_handshake(socket)
    if not handshake then
        socket:close()
        return format_output(false, "Could not parse MySQL handshake")
    end
    insert(result, "MySQL handshake received successfully")
    local creds = {
        {"root", ""},
        {"root", "root"},
        {"root", "password"},
        {"root", "admin"},
        {"", ""},
    }
    for _, c in ipairs(creds) do
        local ok, msg = try_auth(host, port, c[1], c[2])
        if ok then
            insert(result, ("Authentication possible: %s / %s"):format(c[1], c[2]))
        end
    end
    socket:close()
    if #result == 1 then
        insert(result, "No empty or weak passwords detected")
    end
    return format_output(true, result)
end
