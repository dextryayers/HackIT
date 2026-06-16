local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Checks for rlogin/rsh trust relationships (.rhosts) allowing unauthorized access.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "audit"}

local trust_users = {"root", "nobody", "guest", "test", "admin", "user"}
local trust_from = {"localhost", "127.0.0.1", "trusted.host.com"}

local function rlogin_connect(host, port, remote_user, local_user, terminal)
    remote_user = remote_user or "root"
    local_user = local_user or "root"
    terminal = terminal or "xterm"
    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local null = string.char(0)
        local pkt = null .. remote_user .. null .. local_user .. null .. terminal .. null
        socket:send(pkt)
        local _, resp = socket:receive_bytes(256)
        socket:close()
        local result = nil
        if resp then
            result = {}
            result.response_received = true
            result.length = #resp
            result.remote_user = remote_user
            result.local_user = local_user
            if resp:byte(1) == 0 then
                result.auth_status = "TRUSTED"
                result.trust_relationship = true
            elseif resp:find("Password") or resp:find("password") then
                result.auth_status = "PASSWORD_REQUIRED"
                result.trust_relationship = false
            elseif resp:find("denied") or resp:find("refused") or resp:find("sorry") then
                result.auth_status = "DENIED"
                result.trust_relationship = false
            elseif resp:find("#") or resp:find("$") or resp:find(">") then
                result.auth_status = "TRUSTED_SHELL"
                result.trust_relationship = true
            else
                result.auth_status = "UNKNOWN"
                result.raw_prefix = resp:sub(1, 20):gsub("[\r\n]", " ")
            end
        end
        return result
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return result
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 513 or port.number == 514) end

action = function(host, port)
    local out = stdnse.output_table()
    out.service = "rlogin/rsh Audit"
    out.target = host.ip
    out.port = port.number
    local trust_found = false
    local results = {}
    for _, ru in ipairs(trust_users) do
        for _, lu in ipairs(trust_from) do
            local ok, r = pcall(rlogin_connect, host, port, ru, lu)
            if ok and r and r.response_received then
                results[#results + 1] = r
                if r.trust_relationship then
                    trust_found = true
                end
            end
        end
    end
    out.probes = results
    if trust_found then
        out.status = "TRUST_RELATIONSHIPS_DETECTED"
        out.risk = "CRITICAL"
        out.message = "rlogin/rsh has trust relationships (no password prompt)"
    else
        out.status = "NO_TRUST"
        out.risk = "LOW"
        out.message = "rlogin requires password or authentication configured"
    end
    return out
end
