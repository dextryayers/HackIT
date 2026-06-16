local stdnse = require "stdnse"
local tls = require "tls"

description = [[Enumerates all supported SSL/TLS cipher suites by attempting to connect with each cipher and recording which are accepted. Uses multiple probes, version extraction, and structured output.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local function test_cipher(host, port, protocol, cipher)
    local sock = nmap.new_socket()
    sock:set_timeout(8000)
    local ok, err = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return false end
        local hello = tls.client_hello(protocol, {ciphers = {cipher}})
        sock:send(hello)
        local _, data = sock:receive_buf(tls.server_hello_done, 5000)
        sock:close()
        if data and (data:match("server_hello") or data:match("handshake")) then
            return true
        end
        return false
    end)
    if not ok then
        pcall(function() sock:close() end)
        return false
    end
    return err
end

action = function(host, port)
    local protocols = {"TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3"}
    local ciphers_tls12 = {
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    }
    local result = stdnse.output_table()
    for _, proto in ipairs(protocols) do
        local supported = {}
        for _, cipher in ipairs(ciphers_tls12) do
            if test_cipher(host, port, proto, cipher) then
                table.insert(supported, cipher)
            end
        end
        if #supported > 0 then
            result[proto] = supported
        end
    end
    local sock = nmap.new_socket()
    sock:set_timeout(5000)
    local ok = pcall(function()
        sock:connect(host.ip, port)
        local hello = tls.client_hello("TLSv1.2")
        sock:send(hello)
        local _, data = sock:receive_buf(tls.server_hello_done, 3000)
        if data then
            local ver = data:match("version[%s=]+([%d%.]+)") or data:match("TLS([%d%.]+)")
            if ver then result.server_version = ver end
        end
        sock:close()
    end)
    if not ok then pcall(function() sock:close() end) end
    if next(result) then
        return result
    end
    return stdnse.format_output(false, "Could not enumerate ciphers")
end
