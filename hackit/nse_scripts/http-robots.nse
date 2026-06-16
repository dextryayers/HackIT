local http = require "http"
local stdnse = require "stdnse"

description = [[Fetches and parses /robots.txt to reveal disallowed paths and sitemap references.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local response = http.get(host, port, "/robots.txt")
    if not response or not response.body then
        return stdnse.format_output(false, "No robots.txt found")
    end
    if response.status == 404 then
        return stdnse.format_output(false, "robots.txt not found (404)")
    end
    local body = response.body
    local disallowed = {}
    local sitemaps = {}
    local user_agents = {}
    for line in body:gmatch("[^\r\n]+") do
        local la = line:match("^Disallow:%s*(.*)$")
        if la then disallowed[#disallowed + 1] = la end
        local sm = line:match("^Sitemap:%s*(.*)$")
        if sm then sitemaps[#sitemaps + 1] = sm end
        local ua = line:match("^User%-agent:%s*(.*)$")
        if ua then user_agents[#user_agents + 1] = ua end
    end
    local result = "robots.txt found"
    if #disallowed > 0 then
        result = result .. "\nDisallowed: " .. table.concat(disallowed, ", ")
    end
    if #sitemaps > 0 then
        result = result .. "\nSitemaps: " .. table.concat(sitemaps, ", ")
    end
    if #user_agents > 0 then
        result = result .. "\nUser-agents: " .. table.concat(user_agents, ", ")
    end
    return stdnse.format_output(true, result)
end
