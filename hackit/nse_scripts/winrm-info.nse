local stdnse = require "stdnse"
local http = require "http"
local string = require "string"
local nmap = require "nmap"
local shortport = require "shortport"



-- nmp function cache
local nmap_register = nmap.register_script
local nmap_settitle = nmap.set_title
local nmap_resolve = nmap.resolve
local nmap_get_port_state = nmap.get_port_state
local nmap_set_port_state = nmap.set_port_state
local comm = nmap.comm
local new_socket = nmap.new_socket
local get_timeout = nmap.get_timeout

-- Performance optimizations
local format = string.format
local lower = string.lower
local upper = string.upper
local byte = string.byte
local sub = string.sub
local match = string.match
local gmatch = string.gmatch
local gsub = string.gsub
local find = string.find
local rep = string.rep
local char = string.char
local concat = table.concat
local insert = table.insert
local remove = table.remove
local sort = table.sort
local move = table.move or function(a1, f, e, t, a2)
    if not a2 then a2 = a1 end
    for i = f, e do a2[t + i - f] = a1[i] end
    return a2
end
local tostring = tostring
local tonumber = tonumber
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local unpack = unpack or table.unpack
local setmetatable = setmetatable
local getmetatable = getmetatable
local error = error
local select = select
local clock = nmap.clock
local msleep = nmap.msleep
local sleep = stdnse.sleep
local strsplit = stdnse.strsplit
local format_output = stdnse.format_output
local output_table = stdnse.output_table

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
    local result = output_table()
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
                if lower(server):find("microsoft") or lower(server):find("winrm") or
                   find(content_type, "application/soap") or find(content_type, "wsman") or
                   find(content_type, "application/wsman") then
                    ep_info.detected = "WinRM"
                    ep_info.confidence = "high"
                end
            elseif response.status == 401 then
                ep_info.authenticated = "required"
                if www_auth ~= "" then
                    ep_info.auth_methods = www_auth
                    local methods = {}
                    for m in gmatch(www_auth, "[^, ]+") do
                        insert(methods, m)
                    end
                    ep_info.auth_types = methods
                end
                if lower(server):find("microsoft") or lower(server):find("winrm") then
                    ep_info.detected = "WinRM (with auth)"
                    ep_info.confidence = "high"
                elseif find(www_auth, "Negotiate") or find(www_auth, "Kerberos") or find(www_auth, "NTLM") then
                    ep_info.detected = "WinRM (Windows auth)"
                    ep_info.confidence = "medium"
                end
            elseif response.status == 404 or response.status == 405 then
                if allow ~= "" then
                    ep_info.allowed_methods = allow
                end
            end

            insert(endpoints, ep_info)
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
        return format_output(false, "WinRM service not detected")
    end

    result.winrm_detected = high_confidence or medium_confidence
    result.confidence = high_confidence and "high" or "medium"
    result.endpoints = endpoints
    result.service_name = "Windows Remote Management (WinRM)"

    return format_output(true, result)
end
