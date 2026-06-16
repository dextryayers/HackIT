local stdnse = require "stdnse"
local tls = require "tls"

description = [[Checks whether TLS compression is enabled on the server by requesting DEFLATE compression in the Client Hello and seeing if it is accepted in the Server Hello. Uses multiple compression methods across TLS versions.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function test_compression_method(host, port, method)
    local sock = nmap.new_socket()
    sock:set_timeout(10000)
    local ok, data = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return nil end
        local hello = tls.client_hello("TLSv1.2", {compress = {method, "NULL"}})
        sock:send(hello)
        local _, d = sock:receive_buf(tls.server_hello_done, 8000)
        sock:close()
        return d
    end)
    if not ok then
        pcall(function() sock:close() end)
        return nil
    end
    return data
end

action = function(host, port)
    local methods = {"DEFLATE", "LZS", "BZIP2"}
    local detected = nil
    for _, method in ipairs(methods) do
        local data = test_compression_method(host, port, method)
        if data then
            if data:match(method) then
                detected = method
                break
            end
        end
    end
    local result = stdnse.output_table()
    if detected then
        result.compression = detected
        result.status = "enabled"
    else
        result.compression = "NULL"
        result.status = "disabled"
    end
    return result
end
