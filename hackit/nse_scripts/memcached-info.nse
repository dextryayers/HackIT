local stdnse = require "stdnse"

description = [[Connects to a Memcached server and issues the "stats" command to retrieve server statistics and configuration parameters. Uses structured output with version extraction.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 11211 or port.service == "memcache") end

local commands = {"stats\r\n", "stats settings\r\n", "stats items\r\n", "version\r\n"}

action = function(host, port)
    local sock = nmap.new_socket()
    sock:set_timeout(10000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return end
        local result = stdnse.output_table()
        for _, cmd in ipairs(commands) do
            sock:send(cmd)
            local _, resp = sock:receive_buf("\r\n", 5000)
            if resp then
                for line in resp:gmatch("([^\r\n]+)") do
                    if cmd == "version\r\n" then
                        local ver = line:match("VERSION ([^\r\n]+)")
                        if ver then result.version = ver end
                    else
                        local parts = {}
                        for part in line:gmatch("%S+") do
                            table.insert(parts, part)
                        end
                        if parts[1] == "STAT" and #parts >= 3 then
                            local key = parts[2]
                            local val = parts[3]
                            for i = 4, #parts do
                                val = val .. " " .. parts[i]
                            end
                            if not result[key] then
                                result[key] = val
                            end
                        end
                    end
                end
            end
        end
        sock:close()
        if next(result) then return result end
    end)
    if not ok then
        pcall(function() sock:close() end)
    end
    if not result or not next(result) then
        return stdnse.format_output(false, "Could not parse Memcached stats")
    end
    return result
end
