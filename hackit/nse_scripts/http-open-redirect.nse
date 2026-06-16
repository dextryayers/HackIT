local http = require "http"
local stdnse = require "stdnse"

description = [[Tests for open redirect vulnerabilities by injecting external URLs into redirect parameters.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local test_url = "http://evil.com"
    local redirect_params = {"url", "redirect", "next", "return", "target", "dest", "goto", "out"}
    local results = {}
    for _, param in ipairs(redirect_params) do
        local url = "/?" .. param .. "=" .. test_url
        local response = http.get(host, port, url)
        if response then
            if response.header and response.header["location"] then
                local loc = response.header["location"]
                if loc:find("evil%.com") then
                    results[#results + 1] = "Open redirect via " .. param .. " -> " .. loc
                end
            end
        end
    end
    if #results == 0 then
        return stdnse.format_output(false, "No open redirect detected")
    end
    return stdnse.format_output(true, table.concat(results, "\n"))
end
