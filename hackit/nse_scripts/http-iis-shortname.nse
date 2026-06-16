local http = require "http"
local stdnse = require "stdnse"

description = [[Detects IIS 8.3 shortname disclosure vulnerability by probing tilde-patterned URLs.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local test_patterns = {
        "/~1/",
        "/~1****",
        "/*~1*",
        "/longfold~1/",
    }
    local results = {}
    for _, pattern in ipairs(test_patterns) do
        local resp = http.get(host, port, pattern)
        if resp and resp.status then
            if resp.status == 200 or resp.status == 301 or resp.status == 302 then
                local content_length = resp.header and resp.header["content-length"]
                results[#results + 1] = "Shortname response at " .. pattern .. " (status " .. resp.status .. ")"
            end
        end
    end
    local aspnet_resp = http.get(host, port, "/")
    if aspnet_resp and aspnet_resp.header then
        local server = aspnet_resp.header["server"] or ""
        if server:find("IIS") then
            results[#results + 1] = "IIS server detected: " .. server
        end
        local x_aspnet = aspnet_resp.header["x-aspnet-version"]
        if x_aspnet then
            results[#results + 1] = "ASP.NET version: " .. x_aspnet
        end
    end
    if #results == 0 then
        return stdnse.format_output(false, "No IIS shortname vulnerability detected")
    end
    return stdnse.format_output(true, table.concat(results, "\n"))
end
