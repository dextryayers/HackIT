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

description = [[Checks HSTS (Strict-Transport-Security) header for max-age, includeSubDomains, and preload directives.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local response = http.get(host, port, "/")
    if not response or not response.header then
        return format_output(false, "No response")
    end
    local hsts = response.header["strict-transport-security"]
    if not hsts then
        return format_output(false, "HSTS header not found")
    end
    local results = {}
    insert(results, "HSTS: " .. hsts)
    local max_age = match(hsts, "max%-age=(%d+)")
    if max_age then
        local ma = tonumber(max_age)
        if ma then
            insert(results, "max-age: " .. ma .. " seconds (" .. math.floor(ma / 86400) .. " days)")
            if ma < 10886400 then
                insert(results, "WARNING: max-age less than recommended (126 days)")
            end
        end
    else
        insert(results, "WARNING: No max-age directive")
    end
    if find(hsts, "includeSubDomains") then
        insert(results, "includeSubDomains: YES")
    else
        insert(results, "includeSubDomains: NO (subdomains not covered)")
    end
    if find(hsts, "preload") then
        insert(results, "preload: YES (eligible for browser preload lists)")
    end
    return format_output(true, concat(results, "\n"))
end
