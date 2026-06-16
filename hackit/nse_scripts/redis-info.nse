local stdnse = require "stdnse"

description = [[Connects to a Redis server and issues the INFO command to retrieve configuration, statistics, and server information. Uses structured output with version extraction and categorized sections.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 6379 or port.service == "redis") end

action = function(host, port)
    local sock = nmap.new_socket()
    sock:set_timeout(10000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return end
        sock:send("*1\r\n$4\r\nINFO\r\n")
        local _, resp = sock:receive_buf("\r\n", 5000)
        if not resp then sock:close(); return end
        local res = stdnse.output_table()
        if resp:match("%$") then
            local len = resp:match("%$(%d+)")
            if len then
                local _, data = sock:receive_buf("\r\n", 5000)
                sock:close()
                if data then
                    local current_section = "general"
                    for line in data:gmatch("([^\r\n]+)") do
                        local section = line:match("^# (.+)$")
                        if section then
                            current_section = section:lower():gsub("%s+", "_")
                            res[current_section] = res[current_section] or {}
                        else
                            local key, val = line:match("^([^:]+):(.+)$")
                            if key and val then
                                if current_section == "general" then
                                    res[key] = val
                                else
                                    if not res[current_section] then
                                        res[current_section] = {}
                                    end
                                    res[current_section][key] = val
                                end
                                if key == "redis_version" then
                                    res.version = val
                                end
                            end
                        end
                    end
                end
            else
                sock:close()
            end
        else
            sock:close()
        end
        if next(res) then return res end
    end)
    if not ok then
        pcall(function() sock:close() end)
    end
    if not result or not next(result) then
        return stdnse.format_output(false, "Could not retrieve Redis info")
    end
    return result
end
