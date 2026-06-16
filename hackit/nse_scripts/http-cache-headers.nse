local http = require "http"
local stdnse = require "stdnse"

description = [[Analyzes Cache-Control, Pragma, Expires, and ETag headers to assess caching behavior and potential information leakage.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local paths = {"/", "/login", "/admin", "/dashboard", "/profile"}
    local results = {}
    for _, path in ipairs(paths) do
        local resp = http.get(host, port, path)
        if resp and resp.header then
            local h = resp.header
            local line = path
            local cache_control = h["cache-control"]
            local pragma = h["pragma"]
            local expires = h["expires"]
            local etag = h["etag"]
            local issues = {}
            if cache_control then
                line = line .. " CC:" .. cache_control
                if cache_control:find("no%-store") then
                elseif cache_control:find("private") then
                    issues[#issues + 1] = "Private cache (may contain sensitive data)"
                elseif cache_control:find("public") and (path == "/login" or path == "/admin") then
                    issues[#issues + 1] = "Sensitive path publicly cacheable"
                end
                if not cache_control:find("no%-store") and not cache_control:find("no%-cache") and not cache_control:find("private") then
                    if path ~= "/" then
                        issues[#issues + 1] = "No cache restriction directive"
                    end
                end
            else
                issues[#issues + 1] = "No Cache-Control header"
            end
            if expires then
                line = line .. " Expires:" .. expires
            end
            if pragma then
                line = line .. " Pragma:" .. pragma
            end
            if etag then
                line = line .. " ETag:" .. etag
            end
            if #issues > 0 then
                line = line .. " [" .. table.concat(issues, "; ") .. "]"
            end
            results[#results + 1] = line
        end
    end
    if #results == 0 then
        return stdnse.format_output(false, "No cache header data available")
    end
    return stdnse.format_output(true, table.concat(results, "\n"))
end
