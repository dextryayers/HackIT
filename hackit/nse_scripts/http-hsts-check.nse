local http = require "http"
local stdnse = require "stdnse"

description = [[Checks HSTS (Strict-Transport-Security) header for max-age, includeSubDomains, and preload directives.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local response = http.get(host, port, "/")
    if not response or not response.header then
        return stdnse.format_output(false, "No response")
    end
    local hsts = response.header["strict-transport-security"]
    if not hsts then
        return stdnse.format_output(false, "HSTS header not found")
    end
    local results = {}
    results[#results + 1] = "HSTS: " .. hsts
    local max_age = hsts:match("max%-age=(%d+)")
    if max_age then
        local ma = tonumber(max_age)
        if ma then
            results[#results + 1] = "max-age: " .. ma .. " seconds (" .. math.floor(ma / 86400) .. " days)"
            if ma < 10886400 then
                results[#results + 1] = "WARNING: max-age less than recommended (126 days)"
            end
        end
    else
        results[#results + 1] = "WARNING: No max-age directive"
    end
    if hsts:find("includeSubDomains") then
        results[#results + 1] = "includeSubDomains: YES"
    else
        results[#results + 1] = "includeSubDomains: NO (subdomains not covered)"
    end
    if hsts:find("preload") then
        results[#results + 1] = "preload: YES (eligible for browser preload lists)"
    end
    return stdnse.format_output(true, table.concat(results, "\n"))
end
