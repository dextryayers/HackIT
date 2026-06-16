local http = require "http"
local stdnse = require "stdnse"

description = [[Follows the redirect chain from the target root URL and reports each hop's status, location, and headers.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local max_hops = 10
    local chain = {}
    local current_url = {host = host, port = port, path = "/", ssl = false}
    local scheme = "http"
    for i = 1, max_hops do
        local resp = http.get(current_url.host, current_url.port, current_url.path, {header = {["User-Agent"] = "HackIT Framework"}})
        if not resp then
            chain[#chain + 1] = "Hop " .. i .. ": No response"
            break
        end
        local status = resp.status or 0
        local loc = resp.header and resp.header["location"]
        local info = "Hop " .. i .. ": " .. scheme .. "://" .. current_url.host .. ":" .. current_url.port .. current_url.path
        info = info .. " -> HTTP " .. status
        if loc then
            info = info .. " (Location: " .. loc .. ")"
        end
        local server = resp.header and resp.header["server"]
        if server then
            info = info .. " [Server: " .. server .. "]"
        end
        chain[#chain + 1] = info
        if status < 300 or status >= 400 then
            chain[#chain + 1] = "Final destination (status " .. status .. ")"
            break
        end
        if loc then
            local new_host, new_port, new_path = loc:match("http[s]?://([^:/]+):?(%d*)(.*)")
            if new_host then
                current_url.host = new_host
                current_url.port = tonumber(new_port) or (loc:find("https") and 443 or 80)
                current_url.path = new_path ~= "" and new_path or "/"
                scheme = loc:find("https") and "https" or "http"
            else
                current_url.path = loc
            end
        else
            break
        end
    end
    if #chain == 0 then
        return stdnse.format_output(false, "No redirect chain data")
    end
    return stdnse.format_output(true, table.concat(chain, "\n"))
end
