local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Detects Spanning Tree Protocol (STP) by looking for BPDU frames.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local function capture_bpdu_frame(timeout)
    timeout = timeout or 5000
    local socket = nmap.new_socket("raw")
    socket:set_timeout(timeout)
    local ok, resp = pcall(function()
        local dst = string.char(0x01, 0x80, 0xc2, 0x00, 0x00, 0x00)
        local src = string.char(0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
        local pkt = dst .. src .. string.char(0x00, 0x26)
        pkt = pkt .. string.char(0x42, 0x42, 0x03, 0x00, 0x00, 0x00)
        socket:send(pkt)
        local _, r = socket:receive_bytes(256)
        socket:close()
        local result = nil
        if r and #r >= 35 then
            result = {}
            result.received = true
            result.length = #r
            result.bpdu_type = (r:byte(20) == 0x00) and "Configuration BPDU" or "TCN BPDU"
            if #r >= 22 then
                local root_id = ""
                for i = 23, 30 do root_id = root_id .. string.format("%02x", r:byte(i)) end
                result.root_bridge_id = root_id
            end
            if #r >= 36 then
                result.root_path_cost = r:byte(36)
            end
        end
        return result
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return resp
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local out = stdnse.output_table()
    out.service = "STP Detection"
    out.target = host.ip
    local frame = capture_bpdu_frame(5000)
    if frame and frame.received then
        out.status = "STP_DETECTED"
        out.stp_active = true
        out.bpdu_length = frame.length
        out.bpdu_type = frame.bpdu_type
        if frame.root_bridge_id then out.root_bridge_id = frame.root_bridge_id end
        if frame.root_path_cost then out.root_path_cost = frame.root_path_cost end
    else
        out.status = "NO_STP"
        out.stp_active = false
        out.message = "No STP BPDU frames detected"
    end
    return out
end
