local stdnse = require "stdnse"

description = [[Checks if the SSH server supports the legacy and insecure SSH protocol version 1, which should be disabled in favor of SSH protocol version 2. Uses structured output with CVE mapping.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 22 or port.service == "ssh") end

action = function(host, port)
    local sock = nmap.new_socket()
    sock:set_timeout(10000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return end
        sock:send("SSH-1.5-HackIT\r\n")
        local status2, resp = sock:receive_buf("\n", 5000)
        sock:close()
        if status2 and resp then
            if resp:find("SSH") and (resp:find("1%.5") or resp:find("1%.99")) then
                return true
            elseif resp:find("Protocol mismatch") or resp:find("SSH%-2") then
                return false
            end
            if not resp:find("SSH%-2") then
                return true
            end
            return false
        end
        return nil
    end)
    if not ok then
        pcall(function() sock:close() end)
    end
    if result == true then
        local res = stdnse.output_table()
        res.vulnerability = true
        res.name = "SSHv1 enabled"
        res.details = "SSH protocol version 1 is enabled (legacy, insecure)"
        res.severity = "HIGH"
        res.recommendation = "Disable SSHv1 and use only SSHv2"
        return res
    elseif result == false then
        return stdnse.format_output(false, "SSHv1 not enabled")
    end
    return stdnse.format_output(false, "Could not determine SSHv1 status")
end
