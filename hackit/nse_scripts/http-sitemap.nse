local http = require "http"
local stdnse = require "stdnse"

description = [[Fetches and parses /sitemap.xml to enumerate URLs and discover hidden paths.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local response = http.get(host, port, "/sitemap.xml")
    if not response or not response.body then
        return stdnse.format_output(false, "No sitemap.xml found")
    end
    if response.status == 404 then
        return stdnse.format_output(false, "sitemap.xml not found (404)")
    end
    local urls = {}
    for loc in response.body:gmatch("<loc>(.-)</loc>") do
        urls[#urls + 1] = loc
    end
    if #urls == 0 then
        return stdnse.format_output(false, "sitemap.xml found but no <loc> entries")
    end
    local count = #urls
    local display = {}
    for i = 1, math.min(count, 20) do
        display[#display + 1] = urls[i]
    end
    if count > 20 then
        display[#display + 1] = "... and " .. (count - 20) .. " more"
    end
    return stdnse.format_output(true, "Found " .. count .. " URLs\n" .. table.concat(display, "\n"))
end
