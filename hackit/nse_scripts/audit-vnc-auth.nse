local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Checks if VNC authentication is enabled.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "audit"}

local auth_type_names = {
    [0] = "Invalid",
    [1] = "None (No Auth)",
    [2] = "VNC Authentication (Standard)",
    [5] = "RA2 (RA2ne)",
    [6] = "RA2ne",
    [16] = "Tight",
    [17] = "Ultra",
    [18] = "TLS",
    [19] = "VeNCrypt",
    [20] = "GTK-VNC SASL",
    [21] = "MD5 Hash",
    [22] = "Colin Dean x",
    [30] = "Apple Remote Desktop",
}

local function vnc_handshake(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local _, banner = socket:receive_bytes(12)
        local result = nil
        if banner and #banner >= 12 then
            result = {}
            result.response_received = true
            result.length = #banner
            result.protocol_version = banner:sub(0, 11):gsub("[\r\n]", "")
            local auth_count = banner:byte(12) or 0
            result.auth_schemes = {}
            result.auth_count = auth_count
            local pos = 13
            for i = 1, auth_count do
                if pos > #banner then break end
                local auth_type = banner:byte(pos) or 0
                result.auth_schemes[#result.auth_schemes + 1] = {
                    code = auth_type,
                    name = auth_type_names[auth_type] or ("Unknown (" .. auth_type .. ")")
                }
                pos = pos + 1
            end
        end
        socket:close()
        return result
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return result
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 5900 or port.number == 5901 or port.number == 5800) end

action = function(host, port)
    local out = stdnse.output_table()
    out.service = "VNC Authentication Audit"
    out.target = host.ip
    out.port = port.number
    local result = vnc_handshake(host, port)
    if result and result.response_received then
        out.protocol_version = result.protocol_version
        out.auth_scheme_count = result.auth_count
        out.auth_schemes = result.auth_schemes
        local has_none = false
        local has_vnc = false
        for _, s in ipairs(result.auth_schemes) do
            if s.code == 1 then has_none = true end
            if s.code == 2 then has_vnc = true end
        end
        if has_none then
            out.status = "NO_AUTH_REQUIRED"
            out.risk = "CRITICAL"
            out.message = "VNC: No authentication required (insecure)"
        elseif has_vnc then
            out.status = "VNC_AUTH_REQUIRED"
            out.risk = "LOW"
            out.message = "VNC: Standard VNC authentication required"
        else
            out.status = "ALTERNATE_AUTH"
            out.risk = "MEDIUM"
            out.message = "VNC: Non-standard authentication in use"
        end
    else
        out.status = "NO_RESPONSE"
        out.message = "Could not determine VNC auth status"
    end
    return out
end
