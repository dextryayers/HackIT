local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local http = require "http"



-- Fast-path bindings for the stdlib and nmap API used by this script.
-- Kept strict-mode safe: every name below is a declared local.
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
local move = table.move
local tostring = tostring
local tonumber = tonumber
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local unpack = table.unpack
local setmetatable = setmetatable
local getmetatable = getmetatable
local error = error
local select = select

local clock = nmap.clock
local msleep = nmap.msleep
local new_socket = nmap.new_socket
local resolve = nmap.resolve

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    return nmap.msleep(math.max(0, math.floor(seconds * 1000)))
end

local strsplit = function(sep, str, max)
    local out, pos, n = {}, 1, 0
    if str == nil then return out end
    while true do
        if max and n >= max - 1 then
            out[#out + 1] = sub(str, pos)
            return out
        end
        local s, e = find(str, sep, pos)
        if not s then
            out[#out + 1] = sub(str, pos)
            return out
        end
        if e < pos then e = pos end
        out[#out + 1] = sub(str, pos, s - 1)
        pos = e + 1
        n = n + 1
        if pos > #str then
            out[#out + 1] = ""
            return out
        end
    end
end

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
