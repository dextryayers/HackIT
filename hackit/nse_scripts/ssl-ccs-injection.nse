local stdnse = require "stdnse"
local tls = require "tls"
local bit = require "bit"

description = [[Tests for the OpenSSL CCS injection vulnerability (CVE-2014-0224) by sending a premature ChangeCipherSpec message. Uses multiple TLS protocol versions and probes for reliable detection.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function build_ccs(version)
    local major, minor
    if version == "TLSv1.0" then major, minor = 0x03, 0x01
    elseif version == "TLSv1.1" then major, minor = 0x03, 0x02
    else major, minor = 0x03, 0x03 end
    return string.char(0x14, major, minor, 0x00, 0x01, 0x01)
end

action = function(host, port)
    local protocols = {"TLSv1.0", "TLSv1.1", "TLSv1.2"}
    for _, proto in ipairs(protocols) do
        local sock = nmap.new_socket()
        sock:set_timeout(10000)
        local ok, result = pcall(function()
            local status = sock:connect(host.ip, port)
            if not status then return end
            local hello = tls.client_hello(proto)
            sock:send(hello)
            local _, data = sock:receive_buf(tls.server_hello_done, 8000)
            if not data then sock:close(); return end
            sock:send(build_ccs(proto))
            local status2, resp = sock:receive_buf("\n", 3000)
            sock:close()
            if status2 and resp and #resp > 0 then
                return resp
            end
        end)
        if not ok then
            pcall(function() sock:close() end)
        end
        if result then
            local res = stdnse.output_table()
            res.vulnerability = "CVE-2014-0224"
            res.name = "CCS Injection"
            res.affected = true
            res.protocol = proto
            res.severity = "HIGH"
            return res
        end
    end
    return stdnse.format_output(false, "Not vulnerable to CCS Injection")
end
