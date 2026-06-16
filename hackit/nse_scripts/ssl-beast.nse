local stdnse = require "stdnse"
local tls = require "tls"

description = [[Tests for the BEAST attack (CVE-2011-3389) by checking if the server supports TLSv1.0 with CBC mode ciphers and does not support TLSv1.1+. Uses structured output with version detection.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function test_protocol_version_cbc(host, port, protocol)
    local sock = nmap.new_socket()
    sock:set_timeout(8000)
    local ok = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return false end
        local hello = tls.client_hello(protocol, {
            ciphers = {
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                "TLS_RSA_WITH_AES_256_CBC_SHA",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            }
        })
        sock:send(hello)
        local _, data = sock:receive_buf(tls.server_hello_done, 5000)
        sock:close()
        return data ~= nil
    end)
    if not ok then
        pcall(function() sock:close() end)
    end
    return ok
end

action = function(host, port)
    local tls10_cbc = test_protocol_version_cbc(host, port, "TLSv1.0")
    local tls11 = test_protocol_version_cbc(host, port, "TLSv1.1")
    if tls10_cbc then
        local result = stdnse.output_table()
        result.vulnerability = "CVE-2011-3389"
        result.name = "BEAST"
        result.affected = true
        result.tls10_cbc_supported = true
        result.tls11_or_higher_available = tls11
        if tls11 then
            result.severity = "LOW"
            result.details = "TLSv1.0 with CBC ciphers supported, but TLSv1.1+ is available (mitigation exists)"
        else
            result.severity = "MEDIUM"
            result.details = "TLSv1.0 with CBC ciphers supported, no TLSv1.1+ available"
        end
        return result
    end
    return stdnse.format_output(false, "Not vulnerable to BEAST")
end
