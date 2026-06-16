local http = require "http"
local stdnse = require "stdnse"

description = [[Fetches the HTML <title> tag from the target web page and returns its content.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local response = http.get(host, port, "/")
    if not response or not response.body then
        return stdnse.format_output(false, "No response from server")
    end
    local title = response.body:match("<title>(.-)</title>")
    if title then
        return stdnse.format_output(true, "Page title: " .. title:gsub("%s+", " "):sub(1, 200))
    end
    return stdnse.format_output(false, "No <title> tag found")
end
