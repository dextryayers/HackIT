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

description = [[Tests which HTTP methods are allowed on the target by sending OPTIONS requests and probing common methods individually.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local options_resp = http.generic_request(host, port, "OPTIONS", "/")
    local allowed = {}
    if options_resp and options_resp.header and options_resp.header["allow"] then
        for m in options_resp.header["allow"]:gmatch("%S+") do
            insert(allowed, m)
        end
    end
    local methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
    local results = {}
    for _, method in ipairs(methods) do
        local resp = http.generic_request(host, port, method, "/")
        if resp and resp.status then
            local status_code = resp.status
            if status_code ~= 405 and status_code ~= 501 and status_code ~= 400 then
                insert(results, method .. " (" .. status_code .. ")")
            end
        end
    end
    if #results == 0 then
        return format_output(false, "No non-standard methods detected")
    end
    if #allowed > 0 then
        insert(results, "OPTIONS Allow: " .. concat(allowed, ", "))
    end
    return format_output(true, "Allowed methods: " .. concat(results, ", "))
end
