local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local http = require "http"



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
Checks for the DigitalOcean metadata service at 169.254.169.254. Attempts to
access the DigitalOcean-specific metadata endpoint to retrieve droplet
information such as hostname, region, and user-data.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(80, "http")

action = function(host, port)
    local result = {}
    local meta_host = "169.254.169.254"
    local meta_socket = new_socket()
    meta_socket:set_timeout(3000)
    local status, err = meta_socket:connect(meta_host, 80)
    if not status then
        return format_output(false, "Metadata service not accessible: " .. tostring(err))
    end
    local paths = {
        "/metadata/v1/id",
        "/metadata/v1/hostname",
        "/metadata/v1/region",
        "/metadata/v1/user-data",
        "/metadata/v1/private-networks",
        "/metadata/v1/public-keys",
        "/metadata/v1/interfaces/private/0/ipv4/address",
        "/metadata/v1/interfaces/public/0/ipv4/address",
    }
    for _, path in ipairs(paths) do
        meta_socket:send("GET " .. path .. " HTTP/1.1\r\nHost: metadata\r\nConnection: close\r\n\r\n")
        local status, response = meta_socket:receive_bytes(1)
        if status and response then
            local body = response:match("\r\n\r\n(.*)")
            if body and #body > 0 and not body:match("404") and not body:match("Not Found") then
                insert(result, ("DigitalOcean metadata: %s = %s"):format(path, (body:gsub("%s+", " "):sub(1, 100))))
            end
        end
    end
    meta_socket:close()
    if #result == 0 then
        insert(result, "DigitalOcean metadata service not available")
    end
    return format_output(true, result)
end
