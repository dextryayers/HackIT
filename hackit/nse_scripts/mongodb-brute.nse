local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"



-- nmp function cache
local nmap_register = nmap.register_script
local nmap_settitle = nmap.set_title
local nmap_resolve = nmap.resolve
local nmap_get_port_state = nmap.get_port_state
local nmap_set_port_state = nmap.set_port_state
local comm = nmap.comm
local new_socket = nmap.new_socket
local get_timeout = nmap.get_timeout

-- Performance optimizations
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
local move = table.move or function(a1, f, e, t, a2)
    if not a2 then a2 = a1 end
    for i = f, e do a2[t + i - f] = a1[i] end
    return a2
end
local tostring = tostring
local tonumber = tonumber
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local unpack = unpack or table.unpack
local setmetatable = setmetatable
local getmetatable = getmetatable
local error = error
local select = select
local clock = nmap.clock
local msleep = nmap.msleep
local sleep = stdnse.sleep
local strsplit = stdnse.strsplit
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
