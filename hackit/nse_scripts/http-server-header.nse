local http = require "http"
local stdnse = require "stdnse"

description = [[Extracts the Server header from the HTTP response to identify the web server software.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local response = http.get(host, port, "/")
    if not response then
        return stdnse.format_output(false, "No response from server")
    end
    local server = response.header and response.header["server"]
    if server then
        return stdnse.format_output(true, "Server: " .. server)
    end
    return stdnse.format_output(false, "No Server header found")
end
