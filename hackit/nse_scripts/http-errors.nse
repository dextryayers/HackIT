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

description = [[Analyzes error pages for information disclosure by requesting non-existent paths and capturing error details.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local test_paths = {
        "/nonexistent12345.html",
        "/test.asp",
        "/test.aspx",
        "/test.php",
        "/test.jsp",
        "/test.cfm",
    }
    local results = {}
    for _, path in ipairs(test_paths) do
        local resp = http.get(host, port, path)
        if resp and resp.body and resp.body ~= "" then
            local info = {}
            if resp.find(body, "stack trace", 1, true) or resp.find(body, "Stack Trace", 1, true) then
                insert(info, "Stack trace")
            end
            if resp.find(body, "Warning:", 1, true) or resp.find(body, "Fatal error", 1, true) then
                insert(info, "PHP error")
            end
            if resp.find(body, "Exception", 1, true) then
                insert(info, "Exception details")
            end
            if resp.find(body, "Server Error", 1, true) then
                insert(info, "ASP.NET error")
            end
            if resp.find(body, "root:", 1, true) or resp.find(body, "jetty", 1, true) then
                insert(info, "Java stack trace")
            end
            if resp.find(body, "File not found", 1, true) or resp.find(body, "No such file", 1, true) then
                insert(info, "Path disclosure")
            end
            local path_info = resp.match(body, "in (%S+%.php)")
            if path_info then
                insert(info, "Path disclosed: " .. path_info)
            end
            if #info > 0 then
                insert(results, "Error at " .. path .. " [" .. concat(info, ", ") .. "]")
            end
        end
    end
    if #results == 0 then
        return format_output(false, "No information disclosure in error pages")
    end
    return format_output(true, concat(results, "\n"))
end
