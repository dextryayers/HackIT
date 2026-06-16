local stdnse = require "stdnse"
local tls = require "tls"

description = [[Tests for the FREAK attack (CVE-2015-0204) by checking if the server accepts export-grade RSA cipher suites, allowing a man-in-the-middle to downgrade the connection. Uses structured output with CVE mapping.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function test_export_cipher(host, port, cipher)
    local sock = nmap.new_socket()
    sock:set_timeout(8000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return false end
        local hello = tls.client_hello("TLSv1.0", {ciphers = {cipher}})
        sock:send(hello)
        local _, data = sock:receive_buf(tls.server_hello_done, 5000)
        sock:close()
        if data then
            if data:match("handshake_failure") or data:match("insufficient_security") then
                return false
            end
            return true
        end
        return false
    end)
    if not ok then
        pcall(function() sock:close() end)
        return false
    end
    return result
end

action = function(host, port)
    local export_ciphers = {
        "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
        "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
        "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    }
    local found = {}
    for _, cipher in ipairs(export_ciphers) do
        if test_export_cipher(host, port, cipher) then
            table.insert(found, cipher)
        end
    end
    if #found > 0 then
        local result = stdnse.output_table()
        result.vulnerability = "CVE-2015-0204"
        result.name = "FREAK"
        result.affected = true
        result.ciphers = found
        result.severity = "MEDIUM"
        result.details = "Server accepts export-grade RSA ciphers, allowing connection downgrade"
        return result
    end
    return stdnse.format_output(false, "Not vulnerable to FREAK")
end
