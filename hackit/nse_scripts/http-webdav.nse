local http = require "http"
local stdnse = require "stdnse"

description = [[Scans the target for WebDAV enabled directories and PROPFIND access.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local webdav_paths = {"/", "/webdav/", "/dav/", "/files/", "/uploads/"}
    local results = {}
    for _, path in ipairs(webdav_paths) do
        local propfind_resp = http.generic_request(host, port, "PROPFIND", path)
        if propfind_resp and propfind_resp.status then
            if propfind_resp.status == 207 then
                results[#results + 1] = "WebDAV enabled at " .. path .. " (PROPFIND 207 Multi-Status)"
            elseif propfind_resp.status == 401 or propfind_resp.status == 403 then
                results[#results + 1] = "WebDAV restricted at " .. path .. " (PROPFIND " .. propfind_resp.status .. ")"
            end
        end
        local options_resp = http.generic_request(host, port, "OPTIONS", path)
        if options_resp and options_resp.header and options_resp.header["allow"] then
            local allow = options_resp.header["allow"]
            if allow:find("PROPFIND") or allow:find("MKCOL") or allow:find("MOVE") or allow:find("COPY") then
                results[#results + 1] = "WebDAV methods at " .. path .. ": " .. allow
            end
        end
    end
    if #results == 0 then
        return stdnse.format_output(false, "No WebDAV found")
    end
    return stdnse.format_output(true, table.concat(results, "\n"))
end
