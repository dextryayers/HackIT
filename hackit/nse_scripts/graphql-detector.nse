local stdnse = require "stdnse"
local http = require "http"
local string = require "string"
local json = require "json"
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

description = [[Detects GraphQL endpoints by sending introspection queries. Probes common paths, tests GET and POST methods, and attempts to extract schema type information from responses.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open" and
        (port.service == "http" or port.service == "https" or port.number == 80 or port.number == 443 or port.number == 8080 or port.number == 8443)
end

local graphql_paths = {
    "/graphql", "/gql", "/query", "/api/graphql",
    "/v1/graphql", "/v2/graphql", "/graph", "/gql/v1",
    "/api/v1/graphql", "/api/query", "/graphiql",
    "/graphql/console", "/graphql/graphiql",
    "/api", "/api/v1", "/api/v2",
    "/playground", "/graphql-playground",
    "/graphql/schema", "/gql/schema",
    "/graph", "/api/graph",
    "/v1/playground", "/v2/playground",
    "/.graphql", "/_graphql",
}

local introspection_query = '{"query":"query { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name fields { name type { name kind } } } directives { name } } }"}'

local function probe_graphql(host, port, path)
    local ok, response = pcall(http.post, host, port, path, {
        timeout = 5000,
        header = {
            ["Content-Type"] = "application/json",
            ["Accept"] = "application/json",
        },
        data = introspection_query,
    })

    if ok and response and response.status == 200 and response.body then
        local ok2, parsed = pcall(json.parse, response.body)
        if ok2 and parsed then
            if parsed.data then
                return { method = "POST", data = parsed.data }
            end
            if parsed.errors and #parsed.errors > 0 then
                return { method = "POST", errors = parsed.errors }
            end
        end
    end

    local ok3, get_resp = pcall(http.get, host, port, path .. "?query=" .. introspection_query, {
        timeout = 5000,
        header = { ["Accept"] = "application/json" }
    })
    if ok3 and get_resp and get_resp.status == 200 and get_resp.body then
        local ok4, parsed2 = pcall(json.parse, get_resp.body)
        if ok4 and parsed2 and parsed2.data then
            return { method = "GET", data = parsed2.data }
        end
    end

    local ok5, simple_get = pcall(http.get, host, port, path, {
        timeout = 3000,
        header = { ["Accept"] = "application/json" }
    })
    if ok5 and simple_get and simple_get.status == 200 and simple_get.body then
        local body = simple_get.body
        if body:find("__schema") or body:find("GraphQL") or
           body:find("\"data\"") or body:find("queryType") or
           body:find("mutationType") then
            return { method = "GET", hint = "body signature" }
        end
    end

    return nil
end

action = function(host, port)
    local result = output_table()
    local endpoints = {}

    for _, path in ipairs(graphql_paths) do
        local info = probe_graphql(host, port, path)
        if info then
            local ep = {
                path = path,
                method = info.method,
                detected = true,
            }

            if info.data and info.data.__schema then
                local schema = info.data.__schema
                ep.schema_accessible = true
                if schema.queryType then
                    ep.has_query_type = true
                end
                if schema.mutationType then
                    ep.has_mutation_type = true
                end
                if schema.subscriptionType then
                    ep.has_subscription_type = true
                end
                if schema.types then
                    ep.type_count = #schema.types
                end
                if schema.directives then
                    ep.directive_count = #schema.directives
                end
            end

            if info.errors then
                ep.introspection_blocked = true
                ep.error_hint = info.errors[1] and info.errors[1].message
            end

            insert(endpoints, ep)
        end
    end

    if #endpoints == 0 then
        return format_output(false, "No GraphQL endpoints detected")
    end

    result.endpoints = endpoints
    result.endpoint_count = #endpoints

    local introspection_open = false
    for _, ep in ipairs(endpoints) do
        if ep.schema_accessible then
            introspection_open = true
            break
        end
    end
    result.introspection_open = introspection_open

    return format_output(true, result)
end
