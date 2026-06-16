local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Checks if X11 server allows open access (no authentication).]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "audit"}

local function probe_x11_auth(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local conn_req = string.char(0x6c, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        socket:send(conn_req)
        local _, resp = socket:receive_bytes(128)
        socket:close()
        local result = nil
        if resp and #resp >= 8 then
            result = {}
            result.response_received = true
            result.length = #resp
            result.success_byte = resp:byte(1)
            result.protocol_major = resp:byte(3) or 0
            result.protocol_minor = resp:byte(5) or 0
            if resp:byte(1) == 1 then
                result.auth_required = false
                result.open_access = true
                if #resp >= 8 then
                    result.vendor = resp:sub(7, 8)
                end
            elseif resp:byte(1) == 0 then
                result.auth_required = true
                result.open_access = false
                result.reason_length = (resp:byte(7) or 0) * 256 + (resp:byte(8) or 0)
                if result.reason_length > 0 and #resp >= 8 + result.reason_length then
                    result.reason = resp:sub(9, 8 + result.reason_length)
                end
            end
        end
        return result
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return result
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.number >= 6000 and port.number <= 6063 end

action = function(host, port)
    local out = stdnse.output_table()
    out.service = "X11 Access Audit"
    out.target = host.ip
    out.display = ":" .. (port.number - 6000)
    out.port = port.number
    local result = probe_x11_auth(host, port)
    if result and result.response_received then
        out.protocol_version = result.protocol_major .. "." .. result.protocol_minor
        if result.open_access then
            out.status = "OPEN_ACCESS"
            out.risk = "CRITICAL"
            out.message = "X11 server is open (no auth required)"
        else
            out.status = "AUTH_REQUIRED"
            out.risk = "LOW"
            out.message = "X11 requires authentication"
            if result.reason then out.auth_reason = result.reason end
        end
    else
        out.status = "NO_RESPONSE"
        out.message = "X11 did not respond to connection request"
    end
    return out
end
