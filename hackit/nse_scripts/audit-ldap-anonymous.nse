local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Checks if LDAP anonymous bind is permitted.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "audit"}

local function ldap_anonymous_bind(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local bind_req = string.char(0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00)
        socket:send(bind_req)
        local _, resp = socket:receive_bytes(256)
        socket:close()
        local result = nil
        if resp and #resp > 2 then
            result = {}
            result.response_received = true
            result.length = #resp
            if resp:byte(13) == 0x0a then
                local result_code = resp:byte(14) or 0
                result.result_code = result_code
                if result_code == 0 then
                    result.success = true
                else
                    result.success = false
                end
            end
            local diag = resp:match("([%w%s]+)")
            if diag then result.diagnostic = diag:sub(1, 60) end
        end
        return result
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return result
end

local function ldap_search_base(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local bind_req = string.char(0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00)
        socket:send(bind_req)
        local _, _ = socket:receive_bytes(128)
        local msg_id = string.char(0x02, 0x01, 0x02)
        local search_req = string.char(0x63, 0x00)
        socket:send(string.char(0x30, 0x0d) .. msg_id .. search_req)
        local _, r = socket:receive_bytes(512)
        socket:close()
        return r and #r > 0
    end)
    if not ok then pcall(socket.close, socket) return false end
    return result
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.number == 389 end

action = function(host, port)
    local out = stdnse.output_table()
    out.service = "LDAP Anonymous Access Audit"
    out.target = host.ip
    out.port = port.number
    local bind_result = ldap_anonymous_bind(host, port)
    if bind_result and bind_result.response_received then
        out.response_length = bind_result.length
        out.result_code = bind_result.result_code
        out.anonymous_bind_permitted = bind_result.success
        if bind_result.success then
            out.status = "ANONYMOUS_BIND_PERMITTED"
            out.risk = "HIGH"
            out.message = "LDAP anonymous bind is permitted"
            local search = ldap_search_base(host, port)
            out.search_possible = search
            if search then
                out.status = "ANONYMOUS_SEARCH_POSSIBLE"
                out.risk = "CRITICAL"
                out.message = "LDAP anonymous bind and search are permitted"
            end
        else
            out.status = "ANONYMOUS_BIND_DENIED"
            out.risk = "LOW"
            out.message = "LDAP anonymous bind is not permitted"
        end
    else
        out.status = "NO_RESPONSE"
        out.message = "Could not determine LDAP bind status"
    end
    return out
end
