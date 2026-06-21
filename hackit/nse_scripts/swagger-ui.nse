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

description = [[Detects Swagger/OpenAPI UI endpoints on web servers. Probes common paths, validates swagger.json/openapi.json content, and extracts API specification details when found.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open" and
        (port.service == "http" or port.service == "https" or port.number == 80 or port.number == 443)
end

local swagger_paths = {
    "/swagger", "/swagger/", "/swagger-ui", "/swagger-ui/",
    "/swagger-ui.html", "/swagger/index.html",
    "/api/swagger", "/api/swagger/",
    "/api/docs", "/api/docs/",
    "/docs", "/docs/",
    "/api/v1/swagger", "/api/v2/swagger",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/openapi.json", "/swagger.json",
    "/api/openapi.json", "/api/swagger.json",
    "/v1/swagger.json", "/v2/swagger.json",
    "/v3/swagger.json", "/v1/openapi.json",
    "/swagger-resources", "/api/swagger-resources",
    "/v2/api-docs", "/v3/api-docs",
    "/api-docs", "/api-docs.json",
    "/swagger-ui/swagger.json",
    "/swagger-ui/openapi.json",
    "/swagger/static/swagger.json",
    "/swagger/dist/swagger-ui.css",
    "/swagger/dist/swagger-ui.js",
    "/swagger-ui/index.html",
    "/swagger-ui/swagger-initializer.js",
    "/api/schema", "/api/spec",
}

local swagger_indicators = {
    "swagger-ui", "swaggerUi", "SwaggerUI",
    "swagger-ui-bundle", "swagger-ui-standalone",
    "swagger-ui.css", "swagger-ui.js",
    "openapi", "OpenAPI",
    "swaggerui", "SwaggerUi",
    "\"swagger\"", "\"openapi\"",
    "SwaggerUIBundle", "SwaggerUIStandalonePreset",
    "swagger-initializer",
}

local function check_swagger_json(body)
    local ok, data = pcall(json.parse, body)
    if not ok or not data then return nil end

    local info = {}
    if data.swagger then
        info.version = "Swagger " .. data.swagger
        info.spec_type = "Swagger"
    elseif data.openapi then
        info.version = "OpenAPI " .. data.openapi
        info.spec_type = "OpenAPI"
    else
        return nil
    end

    if data.info then
        info.title = data.info.title
        info.description = data.info.description
        info.api_version = data.info.version
    end

    if data.paths then
        local path_count = 0
        for _ in pairs(data.paths) do path_count = path_count + 1 end
        info.path_count = path_count
    end

    if data.definitions or data.components then
        local defs = data.definitions or (data.components and data.components.schemas)
        if defs then
            local def_count = 0
            for _ in pairs(defs) do def_count = def_count + 1 end
            info.definition_count = def_count
        end
    end

    if data.servers then
        info.servers = data.servers
    end

    if data.host then
        info.host = data.host
        info.base_path = data.basePath
        info.schemes = data.schemes
    end

    if data.securityDefinitions or data.security then
        info.security_defined = true
    end

    return info
end

local function check_swagger_html(body)
    local lbody = body:lower()
    for _, indicator in ipairs(swagger_indicators) do
        if lbody:find(indicator:lower()) then
            return true
        end
    end
    return nil
end

action = function(host, port)
    local result = output_table()
    local endpoints = {}

    for _, path in ipairs(swagger_paths) do
        local ok, response = pcall(http.get, host, port, path, { timeout = 5000 })
        if ok and response and response.status == 200 and response.body then
            local ep_info = { path = path, status = 200 }

            if path:match("%.json$") or path:match("api%-docs") then
                local spec_info = check_swagger_json(response.body)
                if spec_info then
                    ep_info.swagger_detected = true
                    ep_info.spec_type = spec_info.spec_type
                    ep_info.spec_version = spec_info.version
                    ep_info.title = spec_info.title
                    ep_info.api_version = spec_info.api_version
                    ep_info.path_count = spec_info.path_count
                    ep_info.definition_count = spec_info.definition_count
                    ep_info.security_defined = spec_info.security_defined
                end
            end

            if not ep_info.swagger_detected then
                local is_html = check_swagger_html(response.body)
                if is_html then
                    ep_info.swagger_ui_detected = true
                end
            end

            if ep_info.swagger_detected or ep_info.swagger_ui_detected then
                insert(endpoints, ep_info)
            end
        end
    end

    if #endpoints == 0 then
        return format_output(false, "No Swagger/OpenAPI UI endpoints detected")
    end

    result.endpoints = endpoints
    result.endpoint_count = #endpoints

    local spec_count = 0
    for _, ep in ipairs(endpoints) do
        if ep.swagger_detected then spec_count = spec_count + 1 end
    end
    result.spec_files_found = spec_count

    return format_output(true, result)
end
