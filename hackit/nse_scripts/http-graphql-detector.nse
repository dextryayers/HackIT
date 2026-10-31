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
Detects GraphQL endpoints by probing common paths and attempting
introspection queries. If a GraphQL endpoint is found, it executes an
introspection query to enumerate available types, queries, mutations,
and subscriptions.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(80, "http")

action = function(host, port)
    local result = {}
    local graphql_paths = {"/graphql", "/graphql/", "/graph", "/graph/",
        "/gql", "/gql/", "/v1/graphql", "/api/graphql", "/query",
        "/graphql/playground", "/graphiql", "/graphiql/",
        "/api", "/api/graphiql", "/console/graphql"}
    local introspection_query = '{"query":"{__schema{types{name fields{name type{name kind}}}}}"}'
    for _, path in ipairs(graphql_paths) do
        local response = http.get(host, port, path)
        if response and response.status then
            if response.status == 200 then
                insert(result, ("Potential GraphQL endpoint: %s (status %d)"):format(path, response.status))
                local post_resp = http.post(host, port, path, nil, nil, introspection_query)
                if post_resp and post_resp.status == 200 and post_resp.body then
                    if match(post_resp.body or "", "__schema") or match(post_resp.body or "", "types") then
                        insert(result, "  GraphQL confirmed - introspection query succeeded")
                        local type_names = {}
                        for type_name in gmatch(post_resp.body or "", '"name"%s*:%s*"([A-Z][^"]+)"') do
                            if not type_names[type_name] then
                                type_names[type_name] = true
                                insert(result, "  Type: " .. type_name)
                            end
                        end
                    end
                end
            end
        end
    end
    if #result == 0 then
        insert(result, "No GraphQL endpoints detected")
    end
    return format_output(true, result)
end
