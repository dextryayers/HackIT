local http = require "http"
local stdnse = require "stdnse"
local nmap = require "nmap"
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

description = [[Fetches and parses /robots.txt to reveal disallowed paths and sitemap references.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local response = http.get(host, port, "/robots.txt")
    if not response or not response.body then
        return format_output(false, "No robots.txt found")
    end
    if response.status == 404 then
        return format_output(false, "robots.txt not found (404)")
    end
    local body = response.body
    local disallowed = {}
    local sitemaps = {}
    local user_agents = {}
    for line in gmatch(body, "[^\r\n]+") do
        local la = match(line, "^Disallow:%s*(.*)$")
        if la then insert(disallowed, la) end
        local sm = match(line, "^Sitemap:%s*(.*)$")
        if sm then insert(sitemaps, sm) end
        local ua = match(line, "^User%-agent:%s*(.*)$")
        if ua then insert(user_agents, ua) end
    end
    local result = "robots.txt found"
    if #disallowed > 0 then
        result = result .. "\nDisallowed: " .. concat(disallowed, ", ")
    end
    if #sitemaps > 0 then
        result = result .. "\nSitemaps: " .. concat(sitemaps, ", ")
    end
    if #user_agents > 0 then
        result = result .. "\nUser-agents: " .. concat(user_agents, ", ")
    end
    return format_output(true, result)
end
