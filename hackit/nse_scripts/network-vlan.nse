local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Detects VLAN hopping by sending 802.1Q tagged packets.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local vlan_ids = {1, 10, 20, 100, 200, 4095}

local function send_dot1q_probe(host, vlan_id)
    local socket = nmap.new_socket("raw")
    socket:set_timeout(3000)
    local ok, resp = pcall(function()
        local dot1q = string.char(0x81, 0x00, 0x00, vlan_id)
        local dummy = string.char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
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
    local out = stdnse.output_table()
    out.service = "VLAN Detection"
    out.target = host.ip
    local results = {}
    for _, vid in ipairs(vlan_ids) do
        local resp = send_dot1q_probe(host, vid)
        results[#results + 1] = {vlan_id = vid, response = (resp and #resp > 0), response_size = (resp and #resp or 0)}
    end
    out.probes = results
    local responsive_vlans = {}
    for _, r in ipairs(results) do
        if r.response then
            responsive_vlans[#responsive_vlans + 1] = r.vlan_id
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
