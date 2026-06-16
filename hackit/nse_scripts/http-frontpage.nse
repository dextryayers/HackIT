local http = require "http"
local stdnse = require "stdnse"

description = [[Checks for Microsoft FrontPage Server Extensions by probing common FPSE paths and RPC endpoints.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local fpse_paths = {
        "/_vti_inf.html",
        "/_vti_pvt/",
        "/_vti_bin/shtml.dll",
        "/_vti_bin/_vti_aut/author.dll",
        "/_vti_bin/fpcount.exe",
        "/cgi-bin/shtml.dll",
    }
    local results = {}
    for _, path in ipairs(fpse_paths) do
        local resp = http.get(host, port, path)
        if resp and resp.status and resp.status < 400 then
            if resp.body and resp.body:find("FrontPage") or resp.body:find("VERSION") then
                results[#results + 1] = "FPSE detected at " .. path
            elseif resp.status ~= 404 then
                results[#results + 1] = "Possible FPSE at " .. path .. " (status " .. resp.status .. ")"
            end
        end
    end
    if #results == 0 then
        return stdnse.format_output(false, "No FrontPage extensions detected")
    end
    return stdnse.format_output(true, table.concat(results, "\n"))
end
