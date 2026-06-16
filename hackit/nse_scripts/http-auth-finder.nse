local http = require "http"
local stdnse = require "stdnse"

description = [[Scans the target for authentication forms, login endpoints, and HTTP authentication prompts.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local response = http.get(host, port, "/")
    if not response or not response.body then
        return stdnse.format_output(false, "No response body")
    end
    local findings = {}
    if response.header and response.header["www-authenticate"] then
        findings[#findings + 1] = "HTTP Basic/Digest auth: " .. response.header["www-authenticate"]
    end
    local login_paths = {"/login", "/admin", "/wp-admin", "/administrator", "/auth", "/user/login", "/signin", "/account/login"}
    for _, path in ipairs(login_paths) do
        local resp = http.get(host, port, path)
        if resp and resp.status and resp.status < 400 then
            if resp.body:match("<input.-[Tt]ype=[\"']password[\"']") or resp.body:match("<form.-[Pp]assword") then
                findings[#findings + 1] = "Login form at " .. path
            end
        end
    end
    if response.body:match("<input.-[Tt]ype=[\"']password[\"']") then
        findings[#findings + 1] = "Password field found on /"
    end
    if #findings == 0 then
        return stdnse.format_output(false, "No authentication endpoints detected")
    end
    return stdnse.format_output(true, table.concat(findings, "\n"))
end
