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
Discovers common API endpoints on web servers by probing paths such as
/v1, /v2, /api, /rest, /graphql, /swagger, /docs, and /openapi.json.
Reports accessible endpoints with their HTTP status codes.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(80, "http")

action = function(host, port)
    local result = {}
    local api_paths = {
        "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
        "/v1", "/v2", "/v3",
        "/rest", "/rest/", "/rest/v1", "/rest/v2",
        "/graphql", "/graphql/",
        "/swagger", "/swagger/", "/swagger-ui", "/swagger-ui/",
        "/swagger.json", "/swagger.yaml",
        "/openapi.json", "/openapi.yaml",
        "/docs", "/docs/",
        "/api-docs", "/api-docs/",
        "/api/documentation",
        "/api/swagger",
        "/v1/api-docs", "/v2/api-docs",
        "/api/health", "/health", "/healthcheck",
        "/api/status", "/status",
    }
    for _, path in ipairs(api_paths) do
        local response = http.get(host, port, path)
        if response and response.status then
            if response.status >= 200 and response.status < 500 and response.status ~= 404 then
                insert(result, ("%s - HTTP %d"):format(path, response.status))
            end
        end
    end
    if #result == 0 then
        insert(result, "No API endpoints found")
    end
    return format_output(true, result)
end
