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

description = [[Analyzes Content-Security-Policy header directives for misconfigurations and missing protections.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local response = http.get(host, port, "/")
    if not response or not response.header then
        return format_output(false, "No response")
    end
    local csp = response.header["content-security-policy"]
    if not csp then
        return format_output(false, "CSP header not found")
    end
    local results = {}
    insert(results, "CSP: " .. sub(csp, 1, 200))
    if find(csp, "unsafe%-inline") then
        insert(results, "WARNING: 'unsafe-inline' detected (XSS risk)")
    end
    if find(csp, "unsafe%-eval") then
        insert(results, "WARNING: 'unsafe-eval' detected")
    end
    if find(csp, "%*%s") or find(csp, ":%s*%*") then
        insert(results, "WARNING: Wildcard (*) source detected in directives")
    end
    if find(csp, "http://") then
        insert(results, "WARNING: HTTP protocol allowed in CSP")
    end
    if not find(csp, "default%-src") then
        insert(results, "NOTE: No default-src directive (falls back to no restriction)")
    end
    if not find(csp, "script%-src") then
        insert(results, "NOTE: No script-src directive")
    end
    local directives = {}
    for d in gmatch(csp, "([^;]+)") do
        insert(directives, match(d, "^%s*(.-)%s*$"))
    end
    insert(results, "Directives found: " .. #directives)
    return format_output(true, concat(results, "\n"))
end
