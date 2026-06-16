local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Discovers the path MTU by sending ICMP with DF bit and varying sizes.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local function probe_mtu_size(host, port, size)
    local socket = nmap.new_socket()
    socket:set_timeout(3000)
    local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local payload = string.rep("A", size)
        socket:send(payload)
        local _, resp = socket:receive_bytes(256)
        socket:close()
        if resp then
            return {success = true, response_length = #resp, data_match = (#resp > 0)}
        end
        return {success = false, response_length = 0}
    end)
    if not ok then pcall(socket.close, socket) return {success = false} end
    return result
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local out = stdnse.output_table()
    out.service = "Path MTU Discovery"
    out.target = host.ip
    out.port = port.number
    local sizes = {1500, 1492, 1472, 1468, 1450, 1430, 1400, 1350, 1300, 1200, 1000, 576}
    local results = {}
    local max_success = 0
    for _, size in ipairs(sizes) do
        local ok, r = pcall(probe_mtu_size, host, port, size)
        if ok and r and r.success then
            results[#results + 1] = {size = size, status = "SUCCESS"}
            if size > max_success then max_success = size end
        else
            results[#results + 1] = {size = size, status = "FAIL"}
        end
    end
    out.probes = results
    out.mtu_estimate = (max_success > 0) and (max_success + 28) or nil
    out.mtu_confidence = (out.mtu_estimate and out.mtu_estimate >= 1472) and "HIGH" or "MEDIUM"
    return out
end
