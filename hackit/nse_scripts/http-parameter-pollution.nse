local http = require "http"
local stdnse = require "stdnse"

description = [[Tests HTTP Parameter Pollution by sending duplicate parameters and observing behavioral changes in the response.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local test_params = {"id=1&id=2", "user=admin&user=guest", "page=home&page=admin", "action=view&action=delete", "debug=0&debug=1"}
    local results = {}
    for _, param_string in ipairs(test_params) do
        local url = "/?" .. param_string
        local resp = http.get(host, port, url)
        if resp and resp.body then
            local baseline = http.get(host, port, "/")
            if baseline and baseline.body and #resp.body ~= #baseline.body then
                results[#results + 1] = "HPP detected: " .. param_string .. " (response length differs: baseline=" .. #baseline.body .. ", polluted=" .. #resp.body .. ")"
            end
        end
    end
    local post_test = http.post(host, port, "/", {header = {["Content-Type"] = "application/x-www-form-urlencoded"}}, nil, "user=a&user=b")
    if post_test and post_test.status and post_test.status < 500 then
        results[#results + 1] = "POST HPP endpoint responds to duplicate params (status " .. post_test.status .. ")"
    end
    if #results == 0 then
        return stdnse.format_output(false, "No parameter pollution symptoms detected")
    end
    return stdnse.format_output(true, table.concat(results, "\n"))
end
