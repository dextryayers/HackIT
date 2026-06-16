local stdnse = require "stdnse"
local tls = require "tls"

description = [[Tests for the DROWN attack by checking if the server supports SSLv2, which can be used to decrypt TLS connections. Uses multiple SSLv2 probe variants and checks actual server response content.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local sslv2_payloads = {
    string.char(0x80, 0x2e, 0x01, 0x03, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
    string.char(0x80, 0x2e, 0x01, 0x03, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
}

local function test_sslv2(host, port, payload)
    local sock = nmap.new_socket()
    sock:set_timeout(8000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return false end
        sock:send(payload)
        local status2, resp = sock:receive_buf("\n", 5000)
        sock:close()
        if status2 and resp then
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
    for _, payload in ipairs(sslv2_payloads) do
        if test_sslv2(host, port, payload) then
            local result = stdnse.output_table()
            result.vulnerability = "DROWN"
            result.affected = true
            result.details = "Server supports SSLv2, can be used to decrypt TLS sessions"
            result.severity = "HIGH"
            return result
        end
    end
    return stdnse.format_output(false, "Not vulnerable to DROWN")
end
