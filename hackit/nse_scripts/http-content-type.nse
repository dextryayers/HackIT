local http = require "http"
local stdnse = require "stdnse"

description = [[Checks Content-Type and Content-Encoding headers of the main page and common resource paths.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local paths = {"/", "/index.html", "/style.css", "/script.js", "/favicon.ico"}
    local results = {}
    for _, path in ipairs(paths) do
        local resp = http.get(host, port, path)
        if resp and resp.header then
            local ct = resp.header["content-type"]
            local ce = resp.header["content-encoding"]
            local cl = resp.header["content-length"]
            local line = path .. " -> Content-Type: " .. (ct or "missing")
            if ce then
                line = line .. ", Encoding: " .. ce
            end
            if cl then
                line = line .. ", Length: " .. cl
            end
            if not ct then
                line = line .. " [WARNING: No Content-Type]"
            elseif ct:find("text/plain") and (path:find("%.html?$") or path == "/") then
                line = line .. " [NOTE: HTML served as text/plain]"
            end
            results[#results + 1] = line
        end
    end
    if #results == 0 then
        return stdnse.format_output(false, "No content-type information available")
    end
    return stdnse.format_output(true, table.concat(results, "\n"))
end
