local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Detects firewall presence by analyzing TCP packet behavior and TTL patterns.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local firewall_headers = {
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Proxy",
    "VIA",
    "X-Cache",
    "X-Squid",
    "CF-RAY",
    "X-Amz-Cf-Id",
    "Akamai-Origin-Hop",
    "X-Nginx-Proxy",
}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local out = stdnse.output_table()
    out.service = "Firewall Detection"
    out.target = host.ip
    out.port = port.number
    local indicators = {}
    local socket = nmap.new_socket()
    socket:set_timeout(3000)
    local ok, resp = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return {blocked = true, error = err} end
        socket:send("GET / HTTP/1.0\r\nHost: " .. host.ip .. "\r\n\r\n")
        local _, r = socket:receive_bytes(4096)
        socket:close()
        local result = {blocked = false}
        if r then
            result.response = r
            for _, hdr in ipairs(firewall_headers) do
                if r:find(hdr, 1, true) then
                    indicators[#indicators + 1] = hdr .. " header present"
                end
            end
            local server = r:match("Server: ([^\r\n]+)")
            if server then result.server = server end
            local status_code = r:match("HTTP/%d%.%d (%d+)")
            if status_code then result.status_code = tonumber(status_code) end
        end
        return result
    end)
    if not ok then
        pcall(socket.close, socket)
        out.status = "CONNECTION_ERROR"
        out.message = tostring(resp or "unknown error")
        return out
    end
    if resp and resp.blocked then
        out.status = "BLOCKED"
        out.firewall_likely = true
        out.error = resp.error
        return out
    end
    if resp and resp.response then
        if #indicators > 0 then
            out.status = "FIREWALL_DETECTED"
            out.firewall_likely = true
            out.indicators = indicators
        else
            out.status = "CLEAR"
            out.firewall_likely = false
        end
        if resp.server then out.server_header = resp.server end
        if resp.status_code then out.status_code = resp.status_code end
    end
    if host.times and host.times.ttl then
        out.target_ttl = host.times.ttl
        if host.times.ttl < 64 then
            indicators[#indicators + 1] = "TTL < 64 (firewall/proxy may decrement TTL)"
        end
    end
    return out
end
