local stdnse = require "stdnse"
local tls = require "tls"

description = [[Enumerates supported Application-Layer Protocol Negotiation (ALPN) protocols by including an ALPN extension in the Client Hello and parsing the server response. Uses multiple TLS versions and structured output.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local alpn_protocols = {
    "http/1.1", "http/1.0", "h2", "h2c", "spdy/3.1", "spdy/3",
    "spdy/2", "webrtc", "stun.turn", "stun.nat-discovery",
    "coap", "xmpp-client", "xmpp-server", "acme-tls/1",
    "mqtt", "dns-over-tls", "smb2", "ocsp", "h3", "hq-interop",
}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function try_alpn(host, port, protocol)
    local sock = nmap.new_socket()
    sock:set_timeout(10000)
    local ok, data = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return nil end
        local hello = tls.client_hello(protocol, {alpn = alpn_protocols})
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
    local protocols = {"TLSv1.3", "TLSv1.2", "TLSv1.1"}
    local selected = {}
    local supported = {}
    for _, proto in ipairs(protocols) do
        local data = try_alpn(host, port, proto)
        if data then
            for _, alpn in ipairs(alpn_protocols) do
                if data:match(alpn) then
                    supported[alpn] = true
                end
            end
            local sel = data:match("alpn[^%w]*(%S+)") or data:match("selected[%s_]+protocol[%s:=]+([%w%./-]+)")
            if sel then
                selected[sel] = true
            end
        end
    end
    if next(supported) then
        local result = stdnse.output_table()
        result.alpn_protocols = {}
        for k in pairs(supported) do
            table.insert(result.alpn_protocols, k)
        end
        result.selected = {}
        for k in pairs(selected) do
            table.insert(result.selected, k)
        end
        return result
    end
    return stdnse.format_output(false, "No ALPN protocols detected or ALPN not supported")
end
