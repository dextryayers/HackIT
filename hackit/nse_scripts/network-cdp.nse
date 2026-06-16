local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Detects Cisco Discovery Protocol (CDP) frames on the network.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local function capture_cdp_frame(timeout)
    timeout = timeout or 5000
    local socket = nmap.new_socket("raw")
    socket:set_timeout(timeout)
    local ok, resp = pcall(function()
        local dst = string.char(0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc)
        local src = string.char(0x00, 0x00, 0x00, 0x00, 0x00, 0x02)
        local cdp_hdr = string.char(0x00, 0x00, 0x20, 0x00, 0x01)
        local pkt = dst .. src .. cdp_hdr
        socket:send(pkt)
        local _, r = socket:receive_bytes(512)
        socket:close()
        local result = nil
        if r and #r > 20 then
            result = {}
            result.received = true
            result.length = #r
            local pos = 15
            while pos < #r - 3 do
                local tlv_type = (r:byte(pos) or 0) * 256 + (r:byte(pos + 1) or 0)
                local tlv_len = (r:byte(pos + 2) or 0) * 256 + (r:byte(pos + 3) or 0)
                if tlv_len < 4 then break end
                local value = r:sub(pos + 4, pos + tlv_len - 1)
                if tlv_type == 1 then result.device_id = value:gsub("[\r\n]", "") end
                if tlv_type == 4 then result.platform = value:gsub("[\r\n]", "") end
                if tlv_type == 5 then result.capabilities = value:gsub("[\r\n]", "") end
                pos = pos + tlv_len
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
    out.service = "CDP Detection"
    out.target = host.ip
    local frame = capture_cdp_frame(5000)
    if frame and frame.received then
        out.status = "CDP_DETECTED"
        out.cdp_active = true
        out.frame_length = frame.length
        if frame.device_id then out.device_id = frame.device_id end
        if frame.platform then out.platform = frame.platform end
        if frame.capabilities then out.capabilities = frame.capabilities end
    else
        out.status = "NO_CDP"
        out.cdp_active = false
        out.message = "No CDP frames detected"
    end
    return out
end
