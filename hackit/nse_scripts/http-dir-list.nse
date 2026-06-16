local http = require "http"
local stdnse = require "stdnse"

description = [[Checks common directories for directory listing enabled (returns index of files).]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local dirs = {"/", "/images/", "/css/", "/js/", "/uploads/", "/backup/", "/admin/", "/includes/", "/tmp/", "/logs/"}
    local listing_patterns = {
        "Index of /", "<title>Index of", "<h1>Index of",
        "<a href=\"?%?%w", "Parent Directory</a>",
        "Directory listing for", "[To Parent Directory]"
    }
    local results = {}
    for _, dir in ipairs(dirs) do
        local resp = http.get(host, port, dir)
        if resp and resp.body then
            local is_listing = false
            for _, pattern in ipairs(listing_patterns) do
                if resp.body:find(pattern) then
                    is_listing = true
                    break
                end
            end
            if is_listing then
                results[#results + 1] = "Directory listing at " .. dir
            end
        end
    end
    if #results == 0 then
        return stdnse.format_output(false, "No directory listing detected")
    end
    return stdnse.format_output(true, table.concat(results, "\n"))
end
