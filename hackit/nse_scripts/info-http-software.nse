local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Detects HTTP server software and version from Server headers and response analysis.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local http_requests = {
    {method = "GET", path = "/", desc = "Root"},
    {method = "GET", path = "/index.html", desc = "Index"},
    {method = "GET", path = "/admin", desc = "Admin"},
    {method = "GET", path = "/server-status", desc = "Server Status"},
    {method = "OPTIONS", path = "*", desc = "OPTIONS"},
    {method = "HEAD", path = "/", desc = "HEAD"},
}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 80 or port.number == 443 or port.number == 8080) end

action = function(host, port)
    local out = stdnse.output_table()
    out.service = "HTTP Software Detection"
    out.target = host.ip
    out.port = port.number
    local headers_seen = {}
    local versions_seen = {}
    for _, req in ipairs(http_requests) do
        local socket = nmap.new_socket()
        socket:set_timeout(5000)
        local ok, resp = pcall(function()
            local status, err = socket:connect(host, port)
            if not status then return nil end
            local http_req = req.method .. " " .. req.path .. " HTTP/1.1\r\nHost: " .. host.ip .. "\r\nConnection: close\r\n\r\n"
            socket:send(http_req)
            local _, r = socket:receive_bytes(4096)
            socket:close()
            return r
        end)
        if not ok then pcall(socket.close, socket) end
        if resp then
            local server = resp:match("Server: ([^\r\n]+)")
            if server and not headers_seen[server] then
                headers_seen[server] = true
                versions_seen[#versions_seen + 1] = {header = "Server", value = server, request = req.desc}
            end
            local powered = resp:match("X%-Powered%-By: ([^\r\n]+)")
            if powered and not headers_seen["X-Powered-By: " .. powered] then
                headers_seen["X-Powered-By: " .. powered] = true
                versions_seen[#versions_seen + 1] = {header = "X-Powered-By", value = powered, request = req.desc}
            end
            local asp = resp:match("X%-AspNet%-Version: ([^\r\n]+)")
            if asp and not headers_seen["X-AspNet-Version: " .. asp] then
                headers_seen["X-AspNet-Version: " .. asp] = true
                versions_seen[#versions_seen + 1] = {header = "X-AspNet-Version", value = asp, request = req.desc}
            end
            local runtime = resp:match("X%-AspNetMvc%-Version: ([^\r\n]+)")
            if runtime and not headers_seen["X-AspNetMvc-Version: " .. runtime] then
                headers_seen["X-AspNetMvc-Version: " .. runtime] = true
                versions_seen[#versions_seen + 1] = {header = "X-AspNetMvc-Version", value = runtime, request = req.desc}
            end
            local cf = resp:match("CF%-RAY: ([^\r\n]+)")
            if cf then out.cloudflare_ray = cf end
        end
    end
    if #versions_seen > 0 then
        out.status = "HEADERS_FOUND"
        out.headers = versions_seen
    else
        out.status = "NO_HEADERS"
        out.message = "HTTP server active (no version headers disclosed)"
    end
    return out
end
