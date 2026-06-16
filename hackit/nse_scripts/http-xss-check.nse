local http = require "http"
local stdnse = require "stdnse"

description = [[Injects a basic XSS payload into query parameters and checks if it is reflected unsanitized in the response.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local payload = "<script>alert(1)</script>"
    local test_params = {q = payload, search = payload, s = payload, query = payload, term = payload}
    local results = {}
    for param, val in pairs(test_params) do
        local url = "/?" .. param .. "=" .. val
        local response = http.get(host, port, url)
        if response and response.body then
            if response.body:find(payload, 1, true) then
                results[#results + 1] = "Reflected in " .. param .. " parameter"
            end
        end
    end
    if #results == 0 then
        local post_body = "q=" .. payload
        local post_resp = http.post(host, port, "/", {header = {["Content-Type"] = "application/x-www-form-urlencoded"}}, nil, post_body)
        if post_resp and post_resp.body and post_resp.body:find(payload, 1, true) then
            results[#results + 1] = "Reflected in POST body"
        end
    end
    if #results == 0 then
        return stdnse.format_output(false, "No XSS reflection detected in basic test")
    end
    return stdnse.format_output(true, "Potential XSS: " .. table.concat(results, ", "))
end
