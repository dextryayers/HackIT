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

description = [[Checks common directories for directory listing enabled (returns index of files).]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local dirs = {"/", "/images/", "/css/", "/js/", "/uploads/", "/backup/", "/admin/", "/includes/", "/tmp/", "/logs/"}
    local listing_patterns = {
        "Index of /", "<title>Index of", "<h1>Index of",
        "<a href=\"?%?%w", "Parent Directory</a>",
        "Directory listing for", "[To Parent Directory]"
    }
    local results = {}
    for _, dir in ipairs(dirs) do
        local resp = http.get(host, port, dir)
        if resp and resp.body then
            local is_listing = false
            for _, pattern in ipairs(listing_patterns) do
                if resp.body:find(pattern) then
                    is_listing = true
                    break
                end
            end
            if is_listing then
                insert(results, "Directory listing at " .. dir)
            end
        end
    end
    if #results == 0 then
        return format_output(false, "No directory listing detected")
    end
    return format_output(true, concat(results, "\n"))
end
