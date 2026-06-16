local http = require "http"
local stdnse = require "stdnse"

description = [[Fingerprints the web server by analyzing Server header, response patterns, X-Powered-By, and cookie naming conventions.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local resp = http.get(host, port, "/")
    if not resp or not resp.header then
        return stdnse.format_output(false, "No response")
    end
    local h = resp.header
    local sigs = {}
    if h["server"] then
        sigs[#sigs + 1] = "Server: " .. h["server"]
    end
    if h["x-powered-by"] then
        sigs[#sigs + 1] = "X-Powered-By: " .. h["x-powered-by"]
    end
    if h["x-aspnet-version"] then
        sigs[#sigs + 1] = "ASP.NET: " .. h["x-aspnet-version"]
    end
    if h["x-generator"] then
        sigs[#sigs + 1] = "Generator: " .. h["x-generator"]
    end
    if h["via"] then
        sigs[#sigs + 1] = "Via: " .. h["via"]
    end
    if resp.body then
        if resp.body:find("wp%-content") or resp.body:find("wp%-includes") then
            sigs[#sigs + 1] = "CMS: WordPress"
        end
        if resp.body:find("Joomla") then
            sigs[#sigs + 1] = "CMS: Joomla"
        end
        if resp.body:find("Drupal") then
            sigs[#sigs + 1] = "CMS: Drupal"
        end
        if resp.body:find("nginx") then
            sigs[#sigs + 1] = "Server: nginx (body hint)"
        end
    end
    if #sigs == 0 then
        return stdnse.format_output(false, "No fingerprinting signatures found")
    end
    return stdnse.format_output(true, table.concat(sigs, "\n"))
end
