local stdnse = require "stdnse"
local http = require "http"
local string = require "string"
local math = require "math"
local bin = require "bin"

description = [[Tests if the target supports WebSocket upgrade requests. Probes common WebSocket endpoints, validates upgrade responses, and identifies WebSocket version and protocol support.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open"
end

local ws_paths = {
    "/", "/ws", "/chat", "/socket", "/websocket",
    "/api/ws", "/sockjs", "/ws/v1",
    "/ws/chat", "/ws/notification", "/ws/data",
    "/socket.io", "/websocket/",
    "/ws/status", "/ws/health",
    "/stream", "/events", "/realtime",
    "/api/socket", "/api/websocket",
    "/ws-api", "/api/v1/ws",
    "/comet", "/push", "/notification",
}

local ws_versions = { "13", "8", "7" }

local ws_protocols = {
    "chat, superchat",
    "graphql-ws",
    "graphql-transport-ws",
    "v10.stomp",
    "mqtt",
    "wamp",
    "soap",
    "json",
    "xml",
}

local function base64_encode(data)
    local b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    local result = {}
    for i = 1, #data, 3 do
        local b1 = data:byte(i) or 0
        local b2 = data:byte(i + 1) or 0
        local b3 = data:byte(i + 2) or 0
        local triple = b1 * 65536 + b2 * 256 + b3
        table.insert(result, b64chars:sub(math.floor(triple / 262144) % 64 + 1, math.floor(triple / 262144) % 64 + 1))
        table.insert(result, b64chars:sub(math.floor(triple / 4096) % 64 + 1, math.floor(triple / 4096) % 64 + 1))
        table.insert(result, b64chars:sub(math.floor(triple / 64) % 64 + 1, math.floor(triple / 64) % 64 + 1))
        table.insert(result, b64chars:sub(triple % 64 + 1, triple % 64 + 1))
    end
    return table.concat(result)
end

local function generate_ws_key()
    local rand = ""
    for i = 1, 16 do
        rand = rand .. string.char(math.random(65, 90))
    end
    return base64_encode(rand)
end

action = function(host, port)
    local result = stdnse.output_table()
    local endpoints = {}

    for _, path in ipairs(ws_paths) do
        for _, ver in ipairs(ws_versions) do
            local ws_key = generate_ws_key()
            local headers = {
                ["Upgrade"] = "websocket",
                ["Connection"] = "Upgrade",
                ["Sec-WebSocket-Key"] = ws_key,
                ["Sec-WebSocket-Version"] = ver,
                ["Sec-WebSocket-Protocol"] = table.concat(ws_protocols, ", "),
            }

            local ok, request = pcall(http.get, host, port, path, { header = headers, timeout = 5000 })
            if ok and request and request.status then
                local ep_info = {
                    path = path,
                    ws_version = ver,
                    status = request.status,
                }

                local upgrade = (request.header and request.header["upgrade"]) or ""
                local connection = (request.header and request.header["connection"]) or ""
                local accept = (request.header and request.header["sec-websocket-accept"]) or ""
                local protocol = (request.header and request.header["sec-websocket-protocol"]) or ""
                local ws_extensions = (request.header and request.header["sec-websocket-extensions"]) or ""
                local server = (request.header and request.header["server"]) or ""

                if upgrade:lower() == "websocket" and accept ~= "" then
                    ep_info.upgrade_success = true
                    ep_info.accept_key = accept
                    ep_info.selected_protocol = protocol
                    ep_info.extensions = ws_extensions
                    ep_info.server = server
                end

                if request.status == 101 then
                    ep_info.http_101 = true
                    ep_info.upgrade_success = true
                end

                if request.status == 400 or request.status == 426 then
                    ep_info.upgrade_required = true
                    if request.header and request.header["sec-websocket-version"] then
                        ep_info.supported_versions = request.header["sec-websocket-version"]
                    end
                end

                if ep_info.upgrade_success or ep_info.upgrade_required then
                    table.insert(endpoints, ep_info)
                end
            end
        end
    end

    if #endpoints == 0 then
        return stdnse.format_output(false, "WebSocket upgrade not supported")
    end

    result.endpoints = endpoints
    result.endpoint_count = #endpoints

    local ws_supported = false
    for _, ep in ipairs(endpoints) do
        if ep.upgrade_success then ws_supported = true end
    end
    result.websocket_supported = ws_supported

    return stdnse.format_output(true, result)
end
