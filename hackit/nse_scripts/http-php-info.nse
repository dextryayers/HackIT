local http = require "http"
local stdnse = require "stdnse"

description = [[Detects exposed phpinfo() pages by probing common paths and checking for PHP configuration output signatures.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local phpinfo_paths = {"/phpinfo.php", "/info.php", "/php_info.php", "/test.php", "/p.php", "/info.php3", "/phpinfo.php5"}
    local results = {}
    for _, path in ipairs(phpinfo_paths) do
        local resp = http.get(host, port, path)
        if resp and resp.body then
            if resp.body:find("PHP Version") and resp.body:find("phpinfo()") then
                results[#results + 1] = "phpinfo() exposed at " .. path
                local php_version = resp.body:match("PHP Version ([^\n<]+)")
                if php_version then
                    results[#results + 1] = "PHP Version: " .. php_version
                end
                break
            end
        end
    end
    if #results == 0 then
        return stdnse.format_output(false, "No phpinfo() pages detected")
    end
    return stdnse.format_output(true, table.concat(results, "\n"))
end
