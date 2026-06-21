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

description = [[Checks if LDAP anonymous bind is permitted.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "audit"}

local function ldap_anonymous_bind(host, port)
    local socket = new_socket()
    socket:set_timeout(5000)
    local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local bind_req = char(0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00)
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
    local socket = new_socket()
    socket:set_timeout(5000)
    local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local bind_req = char(0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00)
        socket:send(bind_req)
        local _, _ = socket:receive_bytes(128)
        local msg_id = char(0x02, 0x01, 0x02)
        local search_req = char(0x63, 0x00)
        socket:send(char(0x30, 0x0d) .. msg_id .. search_req)
        local _, r = socket:receive_bytes(512)
        socket:close()
        return r and #r > 0
    end)
    if not ok then pcall(socket.close, socket) return false end
    return result
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.number == 389 end

action = function(host, port)
    local out = output_table()
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
