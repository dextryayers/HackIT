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

description = [[Tests if the TRACE method is enabled (Cross-Site Tracing / XST vulnerability).]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local options = {header = {["X-Custom-Test"] = "xst-test-value"}}
    local resp = http.generic_request(host, port, "TRACE", "/", options)
    if not resp or not resp.body then
        return format_output(false, "No response to TRACE request")
    end
    if resp.status == 200 then
        if resp.body:find("X-Custom-Test") and resp.body:find("xst%-test%-value") then
            return format_output(true, "TRACE method is ENABLED - XST vulnerability may exist (request echoed back)")
        end
        return format_output(true, "TRACE method responded with 200 but did not echo headers (may be limited)")
    elseif resp.status == 405 then
        return format_output(false, "TRACE method not allowed (405)")
    elseif resp.status == 501 then
        return format_output(false, "TRACE method not implemented (501)")
    else
        return format_output(false, "TRACE method returned status " .. resp.status)
    end
end
