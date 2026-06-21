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

description = [[Detects VLAN hopping by sending 802.1Q tagged packets.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local vlan_ids = {1, 10, 20, 100, 200, 4095}

local function send_dot1q_probe(host, vlan_id)
    local socket = new_socket("raw")
    socket:set_timeout(3000)
    local ok, resp = pcall(function()
        local dot1q = char(0x81, 0x00, 0x00, vlan_id)
        local dummy = char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        socket:send(dot1q .. dummy)
        local _, r = socket:receive_bytes(256)
        socket:close()
        return r
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return resp
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local out = output_table()
    out.service = "VLAN Detection"
    out.target = host.ip
    local results = {}
    for _, vid in ipairs(vlan_ids) do
        local resp = send_dot1q_probe(host, vid)
        insert(results, {vlan_id = vid, response = (resp and #resp > 0), response_size = (resp and #resp or 0)})
    end
    out.probes = results
    local responsive_vlans = {}
    for _, r in ipairs(results) do
        if r.response then
            insert(responsive_vlans, r.vlan_id)
        end
    end
    if #responsive_vlans > 0 then
        out.vlan_tagging_possible = true
        out.responsive_vlan_ids = responsive_vlans
        out.status = "VLAN_PROBES_RESPONDED"
    else
        out.vlan_tagging_possible = false
        out.status = "NO_VLAN_RESPONSES"
        out.message = "No VLAN hopping detected"
    end
    return out
end
