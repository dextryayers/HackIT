local http = require "http"
local stdnse = require "stdnse"

description = [[Analyzes error pages for information disclosure by requesting non-existent paths and capturing error details.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local test_paths = {
        "/nonexistent12345.html",
        "/test.asp",
        "/test.aspx",
        "/test.php",
        "/test.jsp",
        "/test.cfm",
    }
    local results = {}
    for _, path in ipairs(test_paths) do
        local resp = http.get(host, port, path)
        if resp and resp.body and resp.body ~= "" then
            local info = {}
            if resp.body:find("stack trace", 1, true) or resp.body:find("Stack Trace", 1, true) then
                info[#info + 1] = "Stack trace"
            end
            if resp.body:find("Warning:", 1, true) or resp.body:find("Fatal error", 1, true) then
                info[#info + 1] = "PHP error"
            end
            if resp.body:find("Exception", 1, true) then
                info[#info + 1] = "Exception details"
            end
            if resp.body:find("Server Error", 1, true) then
                info[#info + 1] = "ASP.NET error"
            end
            if resp.body:find("root:", 1, true) or resp.body:find("jetty", 1, true) then
                info[#info + 1] = "Java stack trace"
            end
            if resp.body:find("File not found", 1, true) or resp.body:find("No such file", 1, true) then
                info[#info + 1] = "Path disclosure"
            end
            local path_info = resp.body:match("in (%S+%.php)")
            if path_info then
                info[#info + 1] = "Path disclosed: " .. path_info
            end
            if #info > 0 then
                results[#results + 1] = "Error at " .. path .. " [" .. table.concat(info, ", ") .. "]"
            end
        end
    end
    if #results == 0 then
        return stdnse.format_output(false, "No information disclosure in error pages")
    end
    return stdnse.format_output(true, table.concat(results, "\n"))
end
