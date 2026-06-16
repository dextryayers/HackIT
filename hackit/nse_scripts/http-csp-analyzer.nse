local http = require "http"
local stdnse = require "stdnse"

description = [[Analyzes Content-Security-Policy header directives for misconfigurations and missing protections.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local response = http.get(host, port, "/")
    if not response or not response.header then
        return stdnse.format_output(false, "No response")
    end
    local csp = response.header["content-security-policy"]
    if not csp then
        return stdnse.format_output(false, "CSP header not found")
    end
    local results = {}
    results[#results + 1] = "CSP: " .. csp:sub(1, 200)
    if csp:find("unsafe%-inline") then
        results[#results + 1] = "WARNING: 'unsafe-inline' detected (XSS risk)"
    end
    if csp:find("unsafe%-eval") then
        results[#results + 1] = "WARNING: 'unsafe-eval' detected"
    end
    if csp:find("%*%s") or csp:find(":%s*%*") then
        results[#results + 1] = "WARNING: Wildcard (*) source detected in directives"
    end
    if csp:find("http://") then
        results[#results + 1] = "WARNING: HTTP protocol allowed in CSP"
    end
    if not csp:find("default%-src") then
        results[#results + 1] = "NOTE: No default-src directive (falls back to no restriction)"
    end
    if not csp:find("script%-src") then
        results[#results + 1] = "NOTE: No script-src directive"
    end
    local directives = {}
    for d in csp:gmatch("([^;]+)") do
        directives[#directives + 1] = d:match("^%s*(.-)%s*$")
    end
    results[#results + 1] = "Directives found: " .. #directives
    return stdnse.format_output(true, table.concat(results, "\n"))
end
