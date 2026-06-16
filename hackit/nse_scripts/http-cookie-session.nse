local http = require "http"
local stdnse = require "stdnse"

description = [[Analyzes session cookies for randomness, length, and security attributes.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local resp = http.get(host, port, "/")
    if not resp or not resp.header then
        return stdnse.format_output(false, "No response")
    end
    local cookies = resp.header["set-cookie"]
    if not cookies then
        return stdnse.format_output(false, "No session cookies set")
    end
    if type(cookies) == "string" then
        cookies = {cookies}
    end
    local results = {}
    for _, cookie in ipairs(cookies) do
        local name = cookie:match("^([^=]+)")
        local value = cookie:match("^[^=]+=([^;]+)")
        local analysis = {}
        if name then
            if name:find("[Ss]ession") or name:find("PHPSESSID") or name:find("JSESSIONID") or name:find("ASP%.NET") or name:find("laravel") then
                analysis[#analysis + 1] = "Session cookie detected"
            end
        end
        if value then
            analysis[#analysis + 1] = "Length: " .. #value .. " chars"
            local entropy = 0
            for c in value:gmatch(".") do
                if c:find("[a-z]") then entropy = entropy + 1 end
                if c:find("[A-Z]") then entropy = entropy + 1 end
                if c:find("[0-9]") then entropy = entropy + 2 end
            end
            if entropy < #value * 0.5 then
                analysis[#analysis + 1] = "Low entropy (possible predictability)"
            end
            if value:match("^%d+$") then
                analysis[#analysis + 1] = "WARNING: Numeric only (predictable)"
            end
        end
        if cookie:find("HttpOnly") then
            analysis[#analysis + 1] = "HttpOnly: Yes"
        else
            analysis[#analysis + 1] = "HttpOnly: No"
        end
        if cookie:find("Secure") then
            analysis[#analysis + 1] = "Secure: Yes"
        else
            analysis[#analysis + 1] = "Secure: No"
        end
        local max_age = cookie:match("Max%-Age=(%d+)")
        if max_age then
            analysis[#analysis + 1] = "Max-Age: " .. max_age .. "s"
        end
        results[#results + 1] = name .. ": " .. table.concat(analysis, ", ")
    end
    return stdnse.format_output(true, table.concat(results, "\n"))
end
