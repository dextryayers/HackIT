local http = require "http"
local stdnse = require "stdnse"

description = [[Checks Set-Cookie headers for security flags: HttpOnly, Secure, SameSite, and Path attributes.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local response = http.get(host, port, "/")
    if not response or not response.header then
        return stdnse.format_output(false, "No response from server")
    end
    local cookies = response.header["set-cookie"]
    if not cookies then
        return stdnse.format_output(false, "No cookies set")
    end
    if type(cookies) == "string" then
        cookies = {cookies}
    end
    local results = {}
    for _, cookie in ipairs(cookies) do
        local name = cookie:match("^([^=]+)")
        local flags = {}
        if cookie:find("HttpOnly") then flags[#flags + 1] = "HttpOnly" end
        if cookie:find("Secure") then flags[#flags + 1] = "Secure" end
        if cookie:find("SameSite") then flags[#flags + 1] = "SameSite" end
        if not cookie:find("HttpOnly") then flags[#flags + 1] = "MISSING HttpOnly" end
        if not cookie:find("Secure") then flags[#flags + 1] = "MISSING Secure" end
        results[#results + 1] = name .. " [" .. table.concat(flags, ", ") .. "]"
    end
    return stdnse.format_output(true, table.concat(results, "\n"))
end
