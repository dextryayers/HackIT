local stdnse = require "stdnse"
local tls = require "tls"

description = [[Tests which versions of SSL/TLS the server supports by attempting handshakes with each protocol version: SSLv2, SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, and TLSv1.3. Uses structured output with version string extraction.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function test_protocol(host, port, protocol)
    local sock = nmap.new_socket()
    sock:set_timeout(8000)
    local ok, data = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return false, nil end
        local hello
        if protocol == "SSLv2" then
            hello = string.char(0x80, 0x2e, 0x01, 0x03, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        else
            hello = tls.client_hello(protocol)
        end
        sock:send(hello)
        local status2, d = sock:receive_buf(tls.server_hello_done, 5000)
        sock:close()
        if status2 and d then
            local ver = d:match("version[%s:=]+([%d%.]+)") or d:match("(%u+)%-(%d%.?%d*)") or d:match("([%d%.]+)[%s]*-[%s]*server")
            return true, ver
        end
        return false, nil
    end)
    if not ok then
        pcall(function() sock:close() end)
        return false, nil
    end
    return ok, data
end

action = function(host, port)
    local protocol_list = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
    local result = stdnse.output_table()
    for _, proto in ipairs(protocol_list) do
        local supported, version_str = test_protocol(host, port, proto)
        if supported then
            result[proto] = true
            if version_str then
                result[proto .. "_version"] = version_str
            end
        else
            result[proto] = false
        end
    end
    return result
end
