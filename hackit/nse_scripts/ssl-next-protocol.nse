local stdnse = require "stdnse"
local tls = require "tls"

description = [[Checks for Next Protocol Negotiation (NPN) support by sending a TLS Client Hello with the NPN extension and parsing the server's response for negotiated protocols. Uses multiple TLS versions and structured output.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local npn_protocols = {"http/1.1", "spdy/3.1", "spdy/3", "spdy/2", "h2"}

action = function(host, port)
    local all_negotiated = {}
    for _, proto in ipairs({"TLSv1.2", "TLSv1.1", "TLSv1.0"}) do
        local sock = nmap.new_socket()
        sock:set_timeout(10000)
        local ok, data = pcall(function()
            local status = sock:connect(host.ip, port)
            if not status then return nil end
            local hello = tls.client_hello(proto, {npn = npn_protocols})
            sock:send(hello)
            local _, d = sock:receive_buf(tls.server_hello_done, 8000)
            sock:close()
            return d
        end)
        if not ok then
            pcall(function() sock:close() end)
        end
        if data then
            for _, npn in ipairs(npn_protocols) do
                if data:match(npn) then
                    all_negotiated[npn] = true
                end
            end
        end
    end
    if next(all_negotiated) then
        local result = stdnse.output_table()
        result.npn_negotiated = {}
        for k in pairs(all_negotiated) do
            table.insert(result.npn_negotiated, k)
        end
        result.npn_supported = #result.npn_negotiated > 0
        return result
    end
    return stdnse.format_output(false, "NPN not supported")
end
