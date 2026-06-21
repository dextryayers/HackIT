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
Discovers Spring Boot Actuator endpoints by probing common actuator paths
such as /actuator/health, /actuator/info, /actuator/env, /actuator/beans,
and /actuator/mappings. Reports accessible endpoints which may leak
sensitive configuration information.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(8080, "http")

action = function(host, port)
    local result = {}
    local actuator_paths = {
        "/actuator", "/actuator/",
        "/actuator/health", "/actuator/info",
        "/actuator/env", "/actuator/beans",
        "/actuator/mappings", "/actuator/configprops",
        "/actuator/metrics", "/actuator/loggers",
        "/actuator/threaddump", "/actuator/heapdump",
        "/actuator/httptrace", "/actuator/auditevents",
        "/actuator/scheduledtasks", "/actuator/conditions",
        "/actuator/shutdown",
        "/env", "/beans", "/configprops", "/mappings",
        "/trace", "/dump", "/health", "/info",
        "/metrics", "/loggers",
    }
    for _, path in ipairs(actuator_paths) do
        local response = http.get(host, port, path)
        if response and response.status then
            if response.status == 200 then
                insert(result, ("Spring Actuator: %s (HTTP %d)"):format(path, response.status))
                if response.headers and response.headers["content-type"] then
                    local ct = response.headers["content-type"]
                    if ct:match("application/vnd.spring") or ct:match("application/json") then
                        insert(result, "  Content-Type: " .. ct)
                    end
                end
            elseif response.status == 401 or response.status == 403 then
                insert(result, ("Spring Actuator: %s (HTTP %d - secured)"):format(path, response.status))
            end
        end
    end
    if #result == 0 then
        insert(result, "No Spring Actuator endpoints detected")
    end
    return format_output(true, result)
end
