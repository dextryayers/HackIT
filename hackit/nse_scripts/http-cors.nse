local http = require "http"
local stdnse = require "stdnse"

description = [[Tests the CORS (Cross-Origin Resource Sharing) policy by sending an Origin header and inspecting the response.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local options = {header = {Origin = "http://evil.com"}}
    local response = http.get(host, port, "/", options)
    if not response or not response.header then
        return stdnse.format_output(false, "No response from server")
    end
    local results = {}
    local acao = response.header["access-control-allow-origin"]
    local acac = response.header["access-control-allow-credentials"]
    if acao then
        results[#results + 1] = "Access-Control-Allow-Origin: " .. acao
        if acao == "*" then
            results[#results + 1] = "WARNING: Wildcard origin detected"
        elseif acao:find("evil%.com") then
            results[#results + 1] = "WARNING: Origin reflection detected (misconfiguration)"
        end
    end
    if acac then
        results[#results + 1] = "Access-Control-Allow-Credentials: " .. acac
        if acao == "*" and acac == "true" then
            results[#results + 1] = "WARNING: Wildcard + credentials is insecure"
        end
    end
    if #results == 0 then
        return stdnse.format_output(false, "No CORS headers found")
    end
    return stdnse.format_output(true, table.concat(results, "\n"))
end
