local http = require "http"
local stdnse = require "stdnse"

description = [[Audits HTTP security headers including HSTS, X-Frame-Options, X-Content-Type-Options, CSP, and more.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local response = http.get(host, port, "/")
    if not response or not response.header then
        return stdnse.format_output(false, "No response")
    end
    local h = response.header
    local checks = {
        {"Strict-Transport-Security", "HSTS"},
        {"X-Frame-Options", "Clickjacking protection"},
        {"X-Content-Type-Options", "MIME sniffing protection"},
        {"Content-Security-Policy", "CSP"},
        {"X-XSS-Protection", "XSS filter"},
        {"Referrer-Policy", "Referrer policy"},
        {"Permissions-Policy", "Permissions policy"},
        {"X-Permitted-Cross-Domain-Policies", "Cross-domain policy"}
    }
    local present = {}
    local missing = {}
    for _, check in ipairs(checks) do
        if h[check[1]:lower()] then
            present[#present + 1] = check[2] .. ": " .. h[check[1]:lower()]
        else
            missing[#missing + 1] = check[2] .. " (" .. check[1] .. ")"
        end
    end
    local result = ""
    if #present > 0 then
        result = result .. "Present headers:\n" .. table.concat(present, "\n")
    end
    if #missing > 0 then
        result = result .. (#present > 0 and "\n\n" or "") .. "Missing headers:\n" .. table.concat(missing, "\n")
    end
    if result == "" then
        return stdnse.format_output(false, "No security headers detected")
    end
    return stdnse.format_output(true, result)
end
