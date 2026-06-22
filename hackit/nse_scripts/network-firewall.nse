local stdnse = require "stdnse"
local nmap = require "nmap"
local shortport = require "shortport"



-- nmp function cache
local nmap_register = nmap.register_script
local nmap_settitle = nmap.set_title
local nmap_resolve = nmap.resolve
local nmap_get_port_state = nmap.get_port_state
local nmap_set_port_state = nmap.set_port_state
local comm = nmap.comm
local new_socket = nmap.new_socket
local get_timeout = nmap.get_timeout

-- Performance optimizations
local format = string.format
local lower = string.lower
local upper = string.upper
local byte = string.byte
local sub = string.sub
local match = string.match
local gmatch = string.gmatch
local gsub = string.gsub
local find = string.find
local rep = string.rep
local char = string.char
local concat = table.concat
local insert = table.insert
local remove = table.remove
local sort = table.sort
local move = table.move or function(a1, f, e, t, a2)
    if not a2 then a2 = a1 end
    for i = f, e do a2[t + i - f] = a1[i] end
    return a2
end
local tostring = tostring
local tonumber = tonumber
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local unpack = unpack or table.unpack
local setmetatable = setmetatable
local getmetatable = getmetatable
local error = error
local select = select
local clock = nmap.clock
local msleep = nmap.msleep
local sleep = stdnse.sleep
local strsplit = stdnse.strsplit
local format_output = stdnse.format_output
local output_table = stdnse.output_table

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
    local out = output_table()
    out.service = "Firewall Detection"
    out.target = host.ip
    out.port = port.number
    local indicators = {}
    local socket = new_socket()
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
                if find(r, hdr, 1, true) then
                    insert(indicators, hdr .. " header present")
                end
            end
            local server = match(r, "Server: ([^\r\n]+)")
            if server then result.server = server end
            local status_code = match(r, "HTTP/%d%.%d (%d+)")
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
            insert(indicators, "TTL < 64 (firewall/proxy may decrement TTL)")
        end
    end
    return out
end
