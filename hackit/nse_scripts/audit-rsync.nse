local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Checks if Rsync modules are listable without authentication.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "audit"}

local function rsync_list_modules(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local banner = socket:receive_bytes(256)
        local server_version = nil
        if banner then
            server_version = banner:match("@RSYNCD: ([%d.]+)")
        end
        socket:send("@RSYNCD: 31.0\n")
        socket:receive_bytes(256)
        socket:send("#list\n")
        local _, resp = socket:receive_bytes(4096)
        socket:send("@RSYNCD: EXIT\n")
        socket:close()
        local result = nil
        if resp and #resp > 0 then
            result = {}
            result.response_received = true
            result.length = #resp
            result.server_version = server_version
            result.modules = {}
            for line in resp:gmatch("([^\r\n]+)") do
                if line:find("@RSYNCD:") then
                    result.protocol_line = line
                elseif #line > 0 and not line:find("^%s*$") then
                    local mod_name = line:match("^([%w._-]+)")
                    local mod_comment = line:match("%s+(.+)$")
                    result.modules[#result.modules + 1] = {name = mod_name, comment = mod_comment or ""}
                end
            end
        end
        return result
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return result
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.number == 873 end

action = function(host, port)
    local out = stdnse.output_table()
    out.service = "Rsync Access Audit"
    out.target = host.ip
    out.port = port.number
    local result = rsync_list_modules(host, port)
    if result and result.response_received then
        out.response_length = result.length
        if result.server_version then out.server_version = result.server_version end
        if #result.modules > 0 then
            out.status = "MODULES_ACCESSIBLE"
            out.risk = "HIGH"
            out.modules = result.modules
            out.module_count = #result.modules
        else
            out.status = "NO_MODULES"
            out.message = "No Rsync modules listed"
        end
    else
        out.status = "NO_RESPONSE"
        out.message = "Rsync connection succeeded but no data received"
    end
    return out
end
