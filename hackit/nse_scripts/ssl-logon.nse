local stdnse = require "stdnse"
local http = require "http"

description = [[Connects via HTTPS and checks if the page contains login forms, authentication fields, or common logon page indicators. Uses multiple paths and response analysis.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 443 or port.service == "https") end

local paths = {"/", "/login", "/admin", "/signin", "/auth", "/logon", "/wp-login.php", "/admin/login.php"}

action = function(host, port)
    local all_indicators = {}
    for _, path in ipairs(paths) do
        local ok, response = pcall(function()
            return http.get(host, port, path)
        end)
        if ok and response and response.body then
            local body = response.body:lower()
            local indicators = {
                {"password field", body:find('type="password"')},
                {"login form", body:find('action="[^"]*login') or body:find("action='[^']*login")},
                {"username field", body:find('name="username"') or body:find('name="user"') or body:find('name="login"')},
                {"login keyword in title", body:find("<title>.*login.*</title>")},
                {"sign-in", body:find("sign.?in")},
                {"logon", body:find("logon")},
                {"auth", body:find("authenticate") or body:find("authorization")},
                {"form", body:find("<form")},
            }
            for _, ind in ipairs(indicators) do
                if ind[2] then
                    all_indicators[ind[1]] = (all_indicators[ind[1]] or 0) + 1
                end
            end
        end
    end
    if next(all_indicators) then
        local result = stdnse.output_table()
        result.url = "https://" .. host.ip .. ":" .. port.number .. "/"
        result.indicators = {}
        for k, v in pairs(all_indicators) do
            table.insert(result.indicators, k)
        end
        result.paths_scanned = #paths
        return result
    end
    return stdnse.format_output(false, "No logon page detected")
end
