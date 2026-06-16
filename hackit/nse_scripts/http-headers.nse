local http = require "http"
local stdnse = require "stdnse"

description = [[Dumps all HTTP response headers from the target web server for manual inspection.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local response = http.get(host, port, "/")
    if not response or not response.header then
        return stdnse.format_output(false, "No headers received")
    end
    local results = {}
    for k, v in pairs(response.header) do
        if type(v) == "table" then
            for _, vv in ipairs(v) do
                results[#results + 1] = k .. ": " .. vv
            end
        else
            results[#results + 1] = k .. ": " .. v
        end
    end
    table.sort(results)
    return stdnse.format_output(true, table.concat(results, "\n"))
end
