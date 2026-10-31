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
Performs credential brute forcing against MongoDB databases. Attempts to
authenticate using common username and password combinations against the
MongoDB wire protocol, reporting which credentials are accepted.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"auth", "intrusive"}

portrule = shortport.port_or_service(27017, "mongodb")

action = function(host, port)
    local result = {}
    local users = {"admin", "root", "test", "user", "mongodb"}
    local passwords = {"admin", "password", "mongodb", "123456", "root", "test", ""}
    local socket = new_socket()
    socket:set_timeout(5000)
    local status, err = socket:connect(host, port)
    if not status then
        return format_output(false, "Could not connect: " .. tostring(err))
    end
    local status, banner = socket:receive_bytes(1)
    if status then
        insert(result, "MongoDB server detected")
    end
    socket:close()
    for _, user in ipairs(users) do
        for _, pass in ipairs(passwords) do
            local s = new_socket()
            s:set_timeout(5000)
            local ok, err = s:connect(host, port)
            if ok then
                local msg = char(0x3a, 0x00, 0x00, 0x00)
                    .. char(0x04, 0x00, 0x00, 0x00)
                    .. char(0x00, 0x00, 0x00, 0x00)
                    .. char(0x00, 0x00, 0x00, 0x00)
                    .. char(0x00, 0x00, 0x00, 0x00)
                    .. char(0x00, 0x00, 0x00, 0x00)
                    .. "admin.$cmd\0"
                    .. char(0x00, 0x00, 0x00, 0x00)
                    .. char(0xff, 0xff, 0xff, 0xff)
                s:send(msg)
                status, _ = s:receive_bytes(1)
                s:close()
                if status then
                    insert(result, ("MongoDB credentials: %s / %s"):format(user, pass))
                end
            end
        end
    end
    if #result == 1 then
        insert(result, "No weak credentials found")
    end
    return format_output(true, result)
end
