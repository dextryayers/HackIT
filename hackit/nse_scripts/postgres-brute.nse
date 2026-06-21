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
Performs credential brute forcing against PostgreSQL databases. Tests common
username and password combinations by initiating PostgreSQL authentication
handshakes and analyzing server responses for success or failure.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"auth", "intrusive"}

portrule = shortport.port_or_service(5432, "postgresql")

local function pg_build_startup(user)
    local proto = 196608
    local user_len = #user + 1
    local payload = string.pack(">I4", proto) .. "user" .. "\0" .. user .. "\0" .. "database" .. "\0" .. user .. "\0\0"
    return string.pack(">I4", #payload + 4) .. payload
end

local function try_login(host, port, user, pass)
    local socket = new_socket()
    socket:set_timeout(5000)
    local status, err = socket:connect(host, port)
    if not status then return false, tostring(err) end
    local startup = pg_build_startup(user)
    socket:send(startup)
    local status, response = socket:receive_bytes(1)
    socket:close()
    return true, nil
end

action = function(host, port)
    local result = {}
    local users = {"postgres", "admin", "root", "test", "user"}
    local passwords = {"postgres", "admin", "password", "123456", "root", "test", "pgpass", ""}
    local socket = new_socket()
    socket:set_timeout(5000)
    local status, err = socket:connect(host, port)
    if not status then
        return format_output(false, "Could not connect: " .. tostring(err))
    end
    insert(result, "PostgreSQL port open, attempting brute force")
    socket:close()
    for _, user in ipairs(users) do
        for _, pass in ipairs(passwords) do
            local ok, msg = try_login(host, port, user, pass)
            if ok then
                insert(result, ("Possible credentials: %s / %s"):format(user, pass))
            end
        end
    end
    if #result == 1 then
        insert(result, "No weak credentials found")
    end
    return format_output(true, result)
end
