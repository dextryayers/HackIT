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
                    if post_resp.match(body, "__schema") or post_resp.match(body, "types") then
                        insert(result, "  GraphQL confirmed - introspection query succeeded")
                        local type_names = {}
                        for type_name in post_resp.gmatch(body, '"name"%s*:%s*"([A-Z][^"]+)"') do
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
