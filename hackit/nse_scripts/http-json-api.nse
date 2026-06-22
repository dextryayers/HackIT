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

description = [[Detects JSON API endpoints by probing common paths and analyzing content types, response bodies, and error messages. Identifies RESTful JSON APIs, HAL, JSON:API, and custom JSON-based services.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open" and
        (port.service == "http" or port.service == "https")
end

local json_paths = {
    "/api", "/api/v1", "/api/v2",
    "/api/users", "/api/posts", "/api/items",
    "/api/data", "/api/status", "/api/health",
    "/api/config", "/api/info", "/api/version",
    "/users", "/posts", "/data",
    "/status", "/health", "/version",
    "/v1/users", "/v2/users",
    "/.well-known/ai-plugin.json",
    "/api/me", "/api/profile",
    "/api/search", "/api/query",
    "/api/products", "/api/orders",
    "/api/categories", "/api/tags",
    "/api/comments", "/api/reviews",
    "/api/settings", "/api/preferences",
    "/api/notifications", "/api/messages",
    "/json", "/api/json",
    "/api/v1/items", "/api/v2/items",
}

local function is_json_response(response)
    if not response or not response.status then return false end

    local content_type = (response.header and response.header["content-type"]) or ""
    if find(content_type, "application/json") or find(content_type, "application/hal") or
       find(content_type, "application/vnd%.api") or find(content_type, "text/json") or
       find(content_type, "application/json-patch") or find(content_type, "application/problem+json") then
        return true, content_type
    end

    if response.body and #response.body > 0 then
        local trimmed = response.match(body, "^%s*(.-)%s*$") or response.body
        if byte(trimmed) == 123 or byte(trimmed) == 91 then
            local ok, parsed = pcall(json.parse, trimmed)
            if ok then
                return true, "application/parse-json"
            end
        end
    end

    return false, ""
end

local function probe_json(host, port, path)
    local ok, response = pcall(http.get, host, port, path, {
        timeout = 5000,
        header = {
            ["Accept"] = "application/json, application/hal+json, application/vnd.api+json, text/json",
        }
    })

    if not ok or not response or not response.status then return nil end

    local info = { path = path, status = response.status }

    local is_json, ct = is_json_response(response)
    if is_json then
        info.format = "JSON"
        info.content_type = ct

        if response.body and #response.body > 0 then
            local ok2, data = pcall(json.parse, response.body)
            if ok2 and data then
                info.parsed = true
                if type(data) == "table" then
                    if #data > 0 then
                        info.data_type = "array"
                        info.element_count = #data
                    else
                        info.data_type = "object"
                        local key_count = 0
                        for k in pairs(data) do
                            key_count = key_count + 1
                        end
                        info.key_count = key_count
                        if data.id then info.has_id = true end
                        if data.data then info.has_data_wrapper = true end
                        info.keys = key_count <= 10 and data or nil
                    end
                end
            end
        end

        return info
    end

    if response.status == 401 then
        local ct = (response.header and response.header["content-type"]) or ""
        if find(ct, "json") then
            info.format = "JSON (auth required)"
            info.auth_type = response.header["www-authenticate"]
            return info
        end
    end

    if response.status == 403 then
        local ct = (response.header and response.header["content-type"]) or ""
        if find(ct, "json") then
            info.format = "JSON (forbidden)"
            return info
        end
    end

    if response.status == 400 or response.status == 422 then
        local ct = (response.header and response.header["content-type"]) or ""
        if find(ct, "json") or find(ct, "problem") then
            info.format = "JSON (validation error)"
            return info
        end
    end

    if response.status == 405 then
        local allow = (response.header and response.header["allow"]) or ""
        if allow ~= "" then
            info.allowed_methods = allow
            info.format = "JSON (method not allowed)"
            return info
        end
    end

    return nil
end

action = function(host, port)
    local result = output_table()
    local endpoints = {}

    for _, path in ipairs(json_paths) do
        local info = probe_json(host, port, path)
        if info then
            insert(endpoints, info)
        end
    end

    if #endpoints == 0 then
        return format_output(false, "No JSON API endpoints detected")
    end

    result.endpoints = endpoints
    result.endpoint_count = #endpoints
    result.api_format = "JSON"

    return format_output(true, result)
end
