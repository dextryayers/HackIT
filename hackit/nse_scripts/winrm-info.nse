local stdnse = require "stdnse"
local http = require "http"
local string = require "string"

description = [[Detects Windows Remote Management (WinRM) service on HTTP/HTTPS ports. Probes multiple endpoints, checks authentication methods, and extracts server version and configuration details from response headers.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open" and
        (port.number == 5985 or port.number == 5986 or port.service == "wsman")
end

local winrm_paths = {
    "/wsman", "/WinRM", "/", "/wsman.svc",
    "/wsman/v1", "/wsman/v2",
    "/api/wsman", "/soap/wsman",
}

action = function(host, port)
    local result = stdnse.output_table()
    local scheme = port.number == 5986 and "https" or "http"
    local endpoints = {}

    for _, path in ipairs(winrm_paths) do
        local ok, response = pcall(http.get, host, port, path, { timeout = 5000 })
        if ok and response and response.status then
            local server = (response.header and response.header["server"]) or ""
            local content_type = (response.header and response.header["content-type"]) or ""
            local www_auth = (response.header and response.header["www-authenticate"]) or ""
            local allow = (response.header and response.header["allow"]) or ""

            local ep_info = {
                path = path,
                status = response.status,
                server = server,
                content_type = content_type,
            }

            if response.status == 200 or response.status == 201 then
                if server:lower():find("microsoft") or server:lower():find("winrm") or
                   content_type:find("application/soap") or content_type:find("wsman") or
                   content_type:find("application/wsman") then
                    ep_info.detected = "WinRM"
                    ep_info.confidence = "high"
                end
            elseif response.status == 401 then
                ep_info.authenticated = "required"
                if www_auth ~= "" then
                    ep_info.auth_methods = www_auth
                    local methods = {}
                    for m in www_auth:gmatch("[^, ]+") do
                        table.insert(methods, m)
                    end
                    ep_info.auth_types = methods
                end
                if server:lower():find("microsoft") or server:lower():find("winrm") then
                    ep_info.detected = "WinRM (with auth)"
                    ep_info.confidence = "high"
                elseif www_auth:find("Negotiate") or www_auth:find("Kerberos") or www_auth:find("NTLM") then
                    ep_info.detected = "WinRM (Windows auth)"
                    ep_info.confidence = "medium"
                end
            elseif response.status == 404 or response.status == 405 then
                if allow ~= "" then
                    ep_info.allowed_methods = allow
                end
            end

            table.insert(endpoints, ep_info)
        end
    end

    local high_confidence = false
    local medium_confidence = false

    for _, ep in ipairs(endpoints) do
        if ep.confidence == "high" then high_confidence = true end
        if ep.confidence == "medium" then medium_confidence = true end
    end

    if not high_confidence and not medium_confidence then
        for _, ep in ipairs(endpoints) do
            if ep.status == 401 and ep.auth_types then
                medium_confidence = true
                break
            end
        end
    end

    if not high_confidence and not medium_confidence then
        return stdnse.format_output(false, "WinRM service not detected")
    end

    result.winrm_detected = high_confidence or medium_confidence
    result.confidence = high_confidence and "high" or "medium"
    result.endpoints = endpoints
    result.service_name = "Windows Remote Management (WinRM)"

    return stdnse.format_output(true, result)
end
