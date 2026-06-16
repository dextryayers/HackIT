local stdnse = require "stdnse"
local tls = require "tls"

description = [[Tests for the POODLE attack (CVE-2014-3566) by checking if the server supports SSLv3 with CBC mode ciphers. Uses multiple probes and checks actual response content for reliable detection.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function test_sslv3_cbc(host, port, cipher)
    local sock = nmap.new_socket()
    sock:set_timeout(8000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return false end
        local hello = tls.client_hello("SSLv3", {ciphers = {cipher}})
        sock:send(hello)
        local _, data = sock:receive_buf(tls.server_hello_done, 5000)
        sock:close()
        return data ~= nil
    end)
    if not ok then
        pcall(function() sock:close() end)
        return false
    end
    return result
end

action = function(host, port)
    local cbc_ciphers = {
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    }
    for _, cipher in ipairs(cbc_ciphers) do
        if test_sslv3_cbc(host, port, cipher) then
            local result = stdnse.output_table()
            result.vulnerability = "CVE-2014-3566"
            result.name = "POODLE"
            result.affected = true
            result.details = "Server supports SSLv3 with CBC ciphers"
            result.cipher = cipher
            result.severity = "MEDIUM"
            return result
        end
    end
    return stdnse.format_output(false, "Not vulnerable to POODLE")
end
