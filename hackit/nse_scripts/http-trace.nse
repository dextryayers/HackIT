local http = require "http"
local stdnse = require "stdnse"

description = [[Tests if the TRACE method is enabled (Cross-Site Tracing / XST vulnerability).]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local options = {header = {["X-Custom-Test"] = "xst-test-value"}}
    local resp = http.generic_request(host, port, "TRACE", "/", options)
    if not resp or not resp.body then
        return stdnse.format_output(false, "No response to TRACE request")
    end
    if resp.status == 200 then
        if resp.body:find("X-Custom-Test") and resp.body:find("xst%-test%-value") then
            return stdnse.format_output(true, "TRACE method is ENABLED - XST vulnerability may exist (request echoed back)")
        end
        return stdnse.format_output(true, "TRACE method responded with 200 but did not echo headers (may be limited)")
    elseif resp.status == 405 then
        return stdnse.format_output(false, "TRACE method not allowed (405)")
    elseif resp.status == 501 then
        return stdnse.format_output(false, "TRACE method not implemented (501)")
    else
        return stdnse.format_output(false, "TRACE method returned status " .. resp.status)
    end
end
