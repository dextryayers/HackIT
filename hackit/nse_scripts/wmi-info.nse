local stdnse = require "stdnse"
local nmap = require "nmap"
local http = require "http"
local string = require "string"
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

description = [[Detects Windows Management Instrumentation (WMI) service via RPC endpoint mapper and HTTP probes. Extracts RPC endpoint details and service availability for WBEM/CIMOM.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open" and
        (port.number == 135 or port.number == 5985 or port.number == 5986)
end

local function check_rpc_wmi(host, port_number)
    local socket = new_socket()
    socket:set_timeout(5000)

    local ok, err = pcall(socket.connect, socket, host.ip, port_number)
    if not ok then
        pcall(socket.close, socket)
        return nil
    end

    local rpc_bind = char(
        0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x6a, 0x28, 0x19, 0x39, 0x0c, 0xb1, 0xd0, 0x11,
        0x9b, 0xa8, 0x00, 0xc0, 0x4f, 0xd9, 0x2e, 0xf5,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
        0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
        0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00
    )

    local ok2 = pcall(socket.send, socket, rpc_bind)
    if not ok2 then
        pcall(socket.close, socket)
        return nil
    end

    local ok3, response = pcall(socket.receive_buf, socket, "\x05", 5)
    pcall(socket.close, socket)

    if ok3 and response and #response >= 4 then
        if byte(response, 2) == 0x02 or byte(response, 3) == 0x02 then
            return "WMI_RPC"
        end
        return "RPC_unknown"
    end
    return nil
end

local function check_http_wmi(host, port_number)
    local ok, response = pcall(http.get, host, port_number, "/", { timeout = 5000 })
    if ok and response and response.status then
        local server = (response.header and response.header["server"]) or ""
        local content_type = (response.header and response.header["content-type"]) or ""

        if lower(server):find("microsoft") or
           find(content_type, "application/soap") or
           find(content_type, "wsman") then
            return "WMI_WinRM"
        end

        if response.status == 401 then
            local auth = (response.header and response.header["www-authenticate"]) or ""
            if find(auth, "Negotiate") or find(auth, "NTLM") or find(auth, "Kerberos") then
                return "WMI_WinRM_authed"
            end
        end
    end
    return nil
end

local function probe_epm_endpoints(host, port_number)
    local endpoints = {}
    local probe_uuids = {
        { uuid = "6a281939-0cb1-d011-9ba8-00c04fd92ef5", name = "WMI (WBEM/CIMOM)" },
        { uuid = "000001a0-0000-0000-c000-000000000046", name = "WMI (ILO)" },
        { uuid = "000001a1-0000-0000-c000-000000000046", name = "WMI (ILO + CIMOM)" },
    }

    for _, pr in ipairs(probe_uuids) do
        local socket = new_socket()
        socket:set_timeout(3000)
        local ok, err = pcall(socket.connect, socket, host.ip, port_number)
        if ok then
            local ok2 = pcall(socket.send, socket, rpc_bind or rep("\x00", 40))
            if ok2 then
                local ok3, resp = pcall(socket.receive_buf, socket, "\x05", 3)
                if ok3 and resp then
                    insert(endpoints, pr.name)
                end
            end
        end
        pcall(socket.close, socket)
    end
    return endpoints
end

action = function(host, port)
    local result = output_table()
    local services = {}
    local details = {}

    if port.number == 135 then
        details.rpc_port = true
        local wmi_status = check_rpc_wmi(host, port.number)
        if wmi_status then
            if wmi_status == "WMI_RPC" then
                insert(services, "WMI accessible via RPC endpoint mapper")
                details.wmi_rpc = true
            else
                insert(services, "RPC endpoint mapper reachable on port 135")
                details.rpc_reachable = true
            end
        end

        local epm_endpoints = probe_epm_endpoints(host, port.number)
        if #epm_endpoints > 0 then
            details.epm_endpoints = epm_endpoints
            for _, ep in ipairs(epm_endpoints) do
                insert(services, "RPC endpoint: " .. ep)
            end
        end
    end

    if port.number == 5985 or port.number == 5986 then
        details.http_port = port.number
        local http_status = check_http_wmi(host, port.number)
        if http_status then
            if http_status == "WMI_WinRM" then
                insert(services, "WMI/WinRM service on port " .. port.number)
                details.wmi_winrm = true
            elseif http_status == "WMI_WinRM_authed" then
                insert(services, "WMI/WinRM service (authenticated) on port " .. port.number)
                details.wmi_winrm_authed = true
            end
        end
    end

    if #services == 0 then
        return format_output(false, "WMI service not detected")
    end

    result.services = services
    result.service_count = #services

    for k, v in pairs(details) do
        result[k] = v
    end

    return format_output(true, result)
end
