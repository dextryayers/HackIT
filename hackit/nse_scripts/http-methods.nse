local http = require "http"
local stdnse = require "stdnse"

description = [[Tests which HTTP methods are allowed on the target by sending OPTIONS requests and probing common methods individually.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local options_resp = http.generic_request(host, port, "OPTIONS", "/")
    local allowed = {}
    if options_resp and options_resp.header and options_resp.header["allow"] then
        for m in options_resp.header["allow"]:gmatch("%S+") do
            allowed[#allowed + 1] = m
        end
    end
    local methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
    local results = {}
    for _, method in ipairs(methods) do
        local resp = http.generic_request(host, port, method, "/")
        if resp and resp.status then
            local status_code = resp.status
            if status_code ~= 405 and status_code ~= 501 and status_code ~= 400 then
                results[#results + 1] = method .. " (" .. status_code .. ")"
            end
        end
    end
    if #results == 0 then
        return stdnse.format_output(false, "No non-standard methods detected")
    end
    if #allowed > 0 then
        results[#results + 1] = "OPTIONS Allow: " .. table.concat(allowed, ", ")
    end
    return stdnse.format_output(true, "Allowed methods: " .. table.concat(results, ", "))
end
