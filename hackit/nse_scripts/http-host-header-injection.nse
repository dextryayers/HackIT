local stdnse = require "stdnse"
local http = require "http"
local string = require "string"

description = [[Tests for HTTP Host header injection vulnerabilities. Sends various malformed Host headers and X-Forwarded-Host variants to detect cache poisoning, redirect hijacking, and header injection vectors.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open" and
        (port.service == "http" or port.service == "https")
end

local payloads = {
    { name = "Arbitrary Host", host = "evil.com", xfh = nil },
    { name = "Arbitrary XFH", host = host.ip, xfh = "evil.com" },
    { name = "Both Malicious", host = "evil.com", xfh = "evil.com" },
    { name = "Absolute URL", host = "http://evil.com", xfh = nil },
    { name = "Port Injection", host = host.ip .. ":9999", xfh = nil },
    { name = "SQL Injection", host = host.ip .. "' OR '1'='1", xfh = nil },
    { name = "Host + XFH Diff", host = "attacker.com", xfh = "evil.com" },
    { name = "Subdomain", host = "sub." .. (host.name or host.ip), xfh = nil },
    { name = "IP Variation", host = "127.0.0.1", xfh = nil },
    { name = "Localhost", host = "localhost", xfh = nil },
    { name = "Newline", host = "evil.com%0d%0aX-Injected:%20true", xfh = nil },
    { name = "\tTab Injection", host = "evil.com%09injected:true", xfh = nil },
    { name = "Long Host", host = string.rep("A", 1000) .. ".com", xfh = nil },
    { name = "Empty Host", host = "", xfh = "" },
    { name = "Local IPv6", host = "[::1]", xfh = nil },
    { name = "Multiple XFH", host = host.ip, xfh = "evil1.com, evil2.com" },
}

local function check_host_header(host, port, payload)
    local headers = { ["Host"] = payload.host }
    if payload.xfh then
        headers["X-Forwarded-Host"] = payload.xfh
    end

    local ok, response = pcall(http.get, host, port, "/", { header = headers, timeout = 5000 })
    if not ok or not response or not response.status then
        return nil
    end

    local indicators = {}
    local body_lower = response.body and response.body:lower() or ""

    local injection_patterns = {
        { pattern = "evil%.com", desc = "Host value reflected in body" },
        { pattern = "127%.0%.0%.1", desc = "Internal IP reflected" },
        { pattern = "localhost", desc = "localhost reflected" },
        { pattern = "attacker%.com", desc = "Attacker domain reflected" },
        { pattern = "x%-injected", desc = "Header injection successful" },
        { pattern = "injected[%s]*:[%s]*true", desc = "CRLF injection reflected" },
        { pattern = "root:.*:0:0:", desc = "Path traversal attempt" },
        { pattern = "admin", desc = "Admin panel reflected" },
    }

    for _, ip in ipairs(injection_patterns) do
        if body_lower:find(ip.pattern) then
            table.insert(indicators, ip.desc)
        end
    end

    if response.status == 302 or response.status == 301 then
        local location = (response.header and response.header["location"]) or ""
        local loc_lower = location:lower()
        local redirect_indicators = {
            { pattern = "evil%.com", desc = "Redirect to attacker host" },
            { pattern = "127%.0%.0%.1", desc = "Redirect to localhost" },
            { pattern = "localhost", desc = "Redirect to localhost" },
            { pattern = "attacker%.com", desc = "Redirect to attacker" },
        }
        for _, ri in ipairs(redirect_indicators) do
            if loc_lower:find(ri.pattern) then
                table.insert(indicators, ri.desc)
            end
        end
    end

    if response.status == 200 or response.status == 302 or response.status == 301 then
        if response.header then
            for k, v in pairs(response.header) do
                local kl = k:lower()
                local vl = tostring(v):lower()
                if kl ~= "host" and kl ~= "x-forwarded-host" then
                    if kl == "location" and vl ~= "" then
                        if vl:find(payload.host:lower()) then
                            table.insert(indicators, "Host injected into Location header")
                        end
                    end
                end
            end
        end
    end

    if #indicators > 0 then
        return indicators
    end
    return nil
end

action = function(host, port)
    local result = stdnse.output_table()
    local findings = {}

    for _, payload in ipairs(payloads) do
        local indicators = check_host_header(host, port, payload)
        if indicators then
            local finding = {
                test_name = payload.name,
                host_sent = payload.host,
                xfh_sent = payload.xfh,
                indicators = indicators,
            }
            table.insert(findings, finding)
        end
    end

    if #findings == 0 then
        return stdnse.format_output(false, "No Host header injection vulnerabilities detected")
    end

    result.findings = findings
    result.vulnerable_tests = #findings

    return stdnse.format_output(true, result)
end
