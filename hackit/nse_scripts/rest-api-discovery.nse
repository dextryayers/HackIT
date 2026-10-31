local stdnse = require "stdnse"
local http = require "http"
local string = require "string"
local json = require "json"
local nmap = require "nmap"
local shortport = require "shortport"



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

description = [[Discovers common REST API paths on web servers. Probes for API endpoints, versioned paths, and common resources. Analyzes response codes, content types, and response bodies for API identification.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open" and
        (port.service == "http" or port.service == "https" or port.number == 80 or port.number == 443)
end

local api_paths = {
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/v1.0", "/api/v2.0",
    "/rest", "/rest/v1", "/rest/v2",
    "/api/users", "/api/health", "/api/status",
    "/api/docs", "/swagger", "/openapi",
    "/api/login", "/api/auth", "/api/token",
    "/api/admin", "/api/config", "/api/info",
    "/api/metrics", "/api/version", "/api/ping",
    "/api/me", "/api/profile", "/api/account",
    "/api/search", "/api/query", "/api/data",
    "/api/items", "/api/products", "/api/orders",
    "/api/customers", "/api/inventory", "/api/reports",
    "/v1", "/v2", "/v3",
    "/v1/api", "/v2/api",
    "/api/batch", "/api/upload", "/api/download",
    "/api/export", "/api/import", "/api/sync",
    "/api/notifications", "/api/messages",
    "/api/settings", "/api/preferences",
    "/api/subscriptions", "/api/webhooks",
    "/api/callback", "/api/hook",
    "/.well-known/api",
}

local function classify_api(response, path)
    local info = {
        path = path,
        status = response.status,
        content_type = (response.header and response.header["content-type"]) or "",
    }

    if info.find(content_type, "json") then
        info.format = "JSON"
    elseif info.find(content_type, "xml") then
        info.format = "XML"
    elseif info.find(content_type, "text") then
        info.format = "Text"
    elseif info.find(content_type, "octet") then
        info.format = "Binary"
    else
        info.format = "Unknown"
    end

    if response.status == 200 or response.status == 201 then
        info.access = "Open"
        if response.body and #response.body > 0 then
            info.body_size = #response.body
            if info.find(content_type, "json") or response.byte(body) == 123 then
                local ok, data = pcall(json.parse, response.body)
                if ok and data then
                    info.parsed_json = true
                    local key_count = 0
                    for _ in pairs(data) do key_count = key_count + 1 end
                    info.json_keys = key_count
                end
            end
        end
    elseif response.status == 401 then
        info.access = "Auth Required (401)"
        local www_auth = (response.header and response.header["www-authenticate"]) or ""
        if www_auth ~= "" then
            info.auth_header = www_auth
        end
    elseif response.status == 403 then
        info.access = "Forbidden (403)"
    elseif response.status == 301 or response.status == 302 or response.status == 307 or response.status == 308 then
        info.access = "Redirect"
        info.location = (response.header and response.header["location"]) or ""
        info.redirects_to = info.location
    elseif response.status == 405 then
        local allow = (response.header and response.header["allow"]) or ""
        info.access = "Method Not Allowed"
        info.allowed_methods = allow
    elseif response.status == 400 then
        info.access = "Bad Request"
    elseif response.status == 404 then
        return nil
    end

    if response.header then
        info.server = response.header["server"]
        info.x_powered_by = response.header["x-powered-by"]
        info.x_api_version = response.header["x-api-version"]
        info.rate_limit = response.header["x-rate-limit"]
        info.rate_remaining = response.header["x-rate-remaining"]
    end

    return info
end

action = function(host, port)
    local result = output_table()
    local endpoints = {}

    for _, path in ipairs(api_paths) do
        local ok, response = pcall(http.get, host, port, path, { timeout = 5000 })
        if ok and response and response.status then
            local info = classify_api(response, path)
            if info then
                insert(endpoints, info)
            end
        end
    end

    if #endpoints == 0 then
        return format_output(false, "No REST API endpoints discovered")
    end

    result.endpoints = endpoints
    result.endpoint_count = #endpoints

    local open_count = 0
    local auth_count = 0
    for _, ep in ipairs(endpoints) do
        if ep.access == "Open" then open_count = open_count + 1 end
        if ep.access == "Auth Required (401)" then auth_count = auth_count + 1 end
    end
    result.open_endpoints = open_count
    result.auth_required_endpoints = auth_count

    return format_output(true, result)
end
