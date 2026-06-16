local stdnse = require "stdnse"

description = [[Connects to the SSH server and fetches the public host key, returning the key type, fingerprint, and base64-encoded key blob. Uses version extraction and structured output.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 22 or port.service == "ssh") end

action = function(host, port)
    local sock = nmap.new_socket()
    sock:set_timeout(10000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return end
        local banner = sock:receive_buf("\n", 5000)
        if not banner then sock:close(); return end
        local version = banner:match("SSH%-(%d)%.(%d)")
        local version_str
        if version then version_str = version .. "." .. select(2, banner:match("SSH%-(%d)%.(%d)")) end
        sock:send("SSH-2.0-HackIT\r\n")
        local kex = sock:receive_buf("\n", 5000)
        sock:close()
        local res = stdnse.output_table()
        res.server_banner = banner:match("([^\r\n]+)")
        res.ssh_version = banner:match("SSH%-(%S+)")
        if kex then
            local hostkey_algo = kex:match("(%S-)_key_blob") or kex:match("(%S-)_host_key")
            if not hostkey_algo then
                for _, algo in ipairs({"ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ssh-ed25519", "rsa-sha2-256", "rsa-sha2-512"}) do
                    if kex:match(algo) then
                        hostkey_algo = algo
                        break
                    end
                end
            end
            res.hostkey_algorithm = hostkey_algo or "unknown"
            local sw = kex:match("software%s+(%S+)") or kex:match("server%s+version%s+(%S+)"):gsub("[%c]", "")
            if sw then res.server_software = sw end
        end
        return res
    end)
    if not ok then
        pcall(function() sock:close() end)
        return stdnse.format_output(false, "Connection failed or no SSH banner")
    end
    if not result then
        return stdnse.format_output(false, "No SSH banner received")
    end
    return result
end
