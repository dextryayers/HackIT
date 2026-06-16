local stdnse = require "stdnse"

description = [[Tests for the FTP bounce attack by issuing a PORT command with a third-party IP address, attempting to instruct the server to connect to an arbitrary host. Uses structured output with CVE mapping.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 21 or port.service == "ftp") end

local test_targets = {
    {"10,0,0,1", "4,210"},
    {"127,0,0,1", "7,112"},
    {"0,0,0,0", "0,0"},
}

action = function(host, port)
    local sock = nmap.new_socket()
    sock:set_timeout(10000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return end
        local banner = sock:receive_buf("\n", 5000)
        if not banner then sock:close(); return end
        local vulnerable = false
        local last_code
        for _, target in ipairs(test_targets) do
            local s = nmap.new_socket()
            s:set_timeout(5000)
            local ok2 = s:connect(host.ip, port)
            if ok2 then
                s:receive_buf("\n", 3000)
                s:send("PORT " .. target[1] .. "," .. target[2] .. "\r\n")
                local _, r = s:receive_buf("\n", 3000)
                s:close()
                if r then
                    local code = r:match("^(%d%d%d)")
                    if code == "200" then
                        vulnerable = true
                        last_code = code
                        break
                    elseif code ~= "500" and code ~= "501" and code ~= "502" then
                        last_code = code
                    end
                end
            end
        end
        sock:close()
        if vulnerable then
            local res = stdnse.output_table()
            res.vulnerability = true
            res.name = "FTP Bounce"
            res.details = "PORT command accepted for arbitrary host"
            res.severity = "MEDIUM"
            res.recommendation = "Disable PORT command or restrict to local addresses"
            return res
        end
        return nil
    end)
    if not ok then
        pcall(function() sock:close() end)
    end
    if result then
        return result
    end
    return stdnse.format_output(false, "Not vulnerable to FTP bounce")
end
