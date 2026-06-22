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

description = [[Fetches and parses /sitemap.xml to enumerate URLs and discover hidden paths.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local response = http.get(host, port, "/sitemap.xml")
    if not response or not response.body then
        return format_output(false, "No sitemap.xml found")
    end
    if response.status == 404 then
        return format_output(false, "sitemap.xml not found (404)")
    end
    local urls = {}
    for loc in response.gmatch(body, "<loc>(.-)</loc>") do
        insert(urls, loc)
    end
    if #urls == 0 then
        return format_output(false, "sitemap.xml found but no <loc> entries")
    end
    local count = #urls
    local display = {}
    for i = 1, math.min(count, 20) do
        insert(display, urls[i])
    end
    if count > 20 then
        insert(display, "... and " .. (count - 20) .. " more")
    end
    return format_output(true, "Found " .. count .. " URLs\n" .. concat(display, "\n"))
end
