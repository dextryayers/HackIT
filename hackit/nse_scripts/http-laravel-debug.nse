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
Detects Laravel debug mode by checking for the Laravel framework and probing
debug endpoints. Looks for debug bar, Ignition error pages, and environment
variable leaks that indicate APP_DEBUG=true.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(80, "http")

action = function(host, port)
    local result = {}
    local response = http.get(host, port, "/")
    if not response then
        return format_output(false, "No HTTP response")
    end
    local body = response.body or ""
    if match(body, "Laravel") or match(body, "csrf%-token") then
        insert(result, "Laravel framework detected")
        local debug_endpoints = {
            {"/_debugbar/", "Debugbar"},
            {"/_debugbar/phpinfo", "Debugbar PHP Info"},
            {"/_ignition/health-check", "Ignition health check"},
            {"/_ignition/execute-solution", "Ignition execute solution"},
            {"/_ignition/share-report", "Ignition share report"},
            {"/config", "Config leak"},
            {"/env", "Env leak"},
        }
        for _, ep in ipairs(debug_endpoints) do
            local resp2 = http.get(host, port, ep[1])
            if resp2 and resp2.status and resp2.status < 500 then
                insert(result, ("  %s: %s (HTTP %d)"):format(ep[2], ep[1], resp2.status))
                if ep[1] == "/_debugbar/" and resp2.body then
                    local debug_headers = resp2.headers
                    if debug_headers and debug_headers["x-debugbar-id"] then
                        insert(result, "    Laravel Debugbar ACTIVE - APP_DEBUG likely enabled")
                    end
                end
            end
        end
    else
        insert(result, "Target does not appear to use Laravel")
    end
    return format_output(true, result)
end
