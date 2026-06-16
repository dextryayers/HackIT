local stdnse = require "stdnse"
local tls = require "tls"

description = [[Tests for the CRIME attack (CVE-2012-4929) by checking if the server supports TLS compression, which allows attackers to recover secret data by observing compression ratios. Uses multiple compression methods and structured output.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function test_compression(host, port, proto, method)
    local sock = nmap.new_socket()
    sock:set_timeout(8000)
    local ok, data = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return nil end
        local hello = tls.client_hello(proto, {compress = {method}})
        sock:send(hello)
        local _, d = sock:receive_buf(tls.server_hello_done, 5000)
        sock:close()
        return d
    end)
    if not ok then
        pcall(function() sock:close() end)
        return false
    end
    if data and (data:match(method) or data:match("compression")) then
        return true
    end
    return false
end

action = function(host, port)
    local methods = {"DEFLATE", "LZS", "NULL"}
    local found = {}
    for _, method in ipairs(methods) do
        for _, proto in ipairs({"TLSv1.2", "TLSv1.1", "TLSv1.0"}) do
            if test_compression(host, port, proto, method) then
                found[method] = true
            end
        end
    end
    if next(found) then
        local result = stdnse.output_table()
        result.vulnerability = "CVE-2012-4929"
        result.name = "CRIME"
        result.affected = true
        result.methods = {}
        for k in pairs(found) do
            table.insert(result.methods, k)
        end
        result.severity = "MEDIUM"
        result.details = "TLS compression enabled - allows secret data recovery via compression ratio analysis"
        return result
    end
    return stdnse.format_output(false, "Not vulnerable to CRIME (no TLS compression)")
end
