local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Detects Web Services Dynamic Discovery (WS-Discovery) probes on the network.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local wsd_multicast = "239.255.255.250"
local wsd_port = 3702

local function build_probe_message(types)
    types = types or "wsdp:Device"
    local soap = '<?xml version="1.0" encoding="utf-8"?>'
    soap = soap .. '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"'
    soap = soap .. ' xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
    soap = soap .. ' xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"'
    soap = soap .. ' xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof">'
    soap = soap .. '<soap:Header>'
    soap = soap .. '<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>'
    soap = soap .. '<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>'
    soap = soap .. '<wsa:MessageID>urn:uuid:' .. stdnse.generate_uuid() .. '</wsa:MessageID>'
    soap = soap .. '</soap:Header>'
    soap = soap .. '<soap:Body>'
    soap = soap .. '<wsd:Probe><wsd:Types>' .. types .. '</wsd:Types></wsd:Probe>'
    soap = soap .. '</soap:Body></soap:Envelope>'
    return soap
end

local function probe_wsd(timeout)
    timeout = timeout or 5000
    local socket = nmap.new_socket("udp")
    socket:set_timeout(timeout)
    local ok, resp = pcall(function()
        socket:connect(wsd_multicast, wsd_port, "udp")
        local probe = build_probe_message("wsdp:Device")
        socket:send(probe)
        local _, r = socket:receive_bytes(2048)
        socket:close()
        local result = nil
        if r and #r > 100 then
            result = {}
            result.received = true
            result.length = #r
            result.has_xml = (r:find("<?xml") or r:find("<soap:")) ~= nil
            local xaddrs = r:match("http%s*://([^<]+)")
            if xaddrs then result.xaddrs = xaddrs end
            local types = r:match("<wsd:Types>([^<]+)</wsd:Types>")
            if types then result.types = types end
            local metadata = r:match("<wsd:MetadataVersion>([^<]+)</wsd:MetadataVersion>")
            if metadata then result.metadata_version = tonumber(metadata) end
        end
        return result
    end)
    if not ok then pcall(socket.close, socket) return nil end
    return resp
end

portrule = function(host, port) return port.protocol == "udp" and port.state == "open" and port.number == 3702 end

action = function(host, port)
    local out = stdnse.output_table()
    out.service = "WS-Discovery"
    out.multicast_group = wsd_multicast
    out.port = wsd_port
    local result = probe_wsd(5000)
    if result and result.received then
        out.status = "DEVICES_FOUND"
        out.devices_present = true
        out.response_length = result.length
        out.valid_soap = result.has_xml
        if result.xaddrs then out.xaddrs = result.xaddrs end
        if result.types then out.types_found = result.types end
        if result.metadata_version then out.metadata_version = result.metadata_version end
    else
        out.status = "NO_DEVICES"
        out.devices_present = false
        out.message = "No WS-Discovery responses received"
    end
    return out
end
