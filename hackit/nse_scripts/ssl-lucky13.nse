local stdnse = require "stdnse"
local tls = require "tls"

description = [[Tests for the Lucky13 attack (CVE-2013-0169) by checking if the server supports CBC mode ciphers in TLSv1.0/v1.1, which can expose plaintext via timing side channels. Uses structured output with detected ciphers.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function test_cbc_cipher(host, port, protocol, cipher)
    local sock = nmap.new_socket()
    sock:set_timeout(8000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return false end
        local hello = tls.client_hello(protocol, {ciphers = {cipher}})
        sock:send(hello)
        local _, data = sock:receive_buf(tls.server_hello_done, 5000)
        sock:close()
        if data and (data:match("server_hello") or data:match("handshake") or data:match("certificate")) then
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
    local cbc_ciphers = {
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    }
    local vulnerable_protocols = {"TLSv1.0", "TLSv1.1"}
    local found = {}
    for _, proto in ipairs(vulnerable_protocols) do
        for _, cipher in ipairs(cbc_ciphers) do
            if test_cbc_cipher(host, port, proto, cipher) then
                table.insert(found, proto .. ":" .. cipher)
            end
        end
    end
    if #found > 0 then
        local result = stdnse.output_table()
        result.vulnerability = "CVE-2013-0169"
        result.name = "Lucky13"
        result.affected = true
        result.affected_ciphers = found
        result.severity = "MEDIUM"
        result.details = "CBC mode ciphers in TLS 1.0/1.1 may expose plaintext via timing side channels"
        return result
    end
    return stdnse.format_output(false, "Not vulnerable to Lucky13 (no CBC ciphers in TLS 1.0/1.1)")
end
