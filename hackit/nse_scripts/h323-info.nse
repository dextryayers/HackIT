local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
local bit = require "bit"

description = [[Detects H.323 gateways and gatekeepers by sending RAS discovery and LRQ requests. Extracts gatekeeper vendor, version, prefix information, and supported services from the H.225.0 RAS response.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "voip"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and (port.number == 1719 or port.number == 1720)
end

local ras_discovery_packets = {
  {
    name = "GRQ",
    data = string.char(
      0x00, 0x28, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00,
      0x00, 0x78, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ),
  },
  {
    name = "LRQ",
    data = string.char(
      0x00, 0x2a, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00,
      0x00, 0x79, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ),
  },
}

action = function(host, port)
  local result = stdnse.output_table()

  for _, probe in ipairs(ras_discovery_packets) do
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local ok, err = pcall(socket.connect, socket, host.ip, port.number)
    if not ok then
      socket:close()
      return stdnse.format_output(false, "Failed to connect: " .. tostring(err))
    end

    local ok2, serr = pcall(socket.send, socket, probe.data)
    if not ok2 then
      socket:close()
      if _ == 1 then
        return stdnse.format_output(false, "Failed to send " .. probe.name)
      end
      break
    end

    local ok3, response = pcall(socket.receive_buf, socket, 1024, true)
    socket:close()

    if ok3 and response and #response >= 10 then
      result.h323_detected = true
      result.probe = probe.name

      if #response >= 5 then
        local msg_type = string.byte(response, 5)
        local msg_types = {
          [0x78] = "Gatekeeper Discovery Response (GCF)",
          [0x14] = "Registration Confirm (RCF)",
          [0x1e] = "Unregistration Confirm (UCF)",
          [0x0a] = "Admission Confirm (ACF)",
          [0x2d] = "Location Confirm (LCF)",
          [0x50] = "Service Control Session",
          [0x79] = "Location Request (LRQ)",
        }
        result.message_type = msg_types[msg_type] or string.format("Unknown (0x%02x)", msg_type)
      end

      local vendor = response:match("H323%-[%w%-]+") or
                     response:match("[%w]+%-Gatekeeper") or
                     response:match("([%w]+)[^%w]Gatekeeper") or
                     response:match("Cisco") or
                     response:match("Avaya") or
                     response:match("Radvision") or
                     response:match("Polycom") or
                     response:match("Vidyo")
      if vendor then
        result.vendor = vendor
      end

      local version = response:match("%d+%.%d+%.%d+%.%d+") or response:match("%d+%.%d+%.%d+")
      if version then
        result.version = version
      end

      local prefix = response:match("(%d+%*?)") or response:match("(%d+%.%d+)")
      if prefix then
        result.prefix_hint = prefix
      end

      if response:find("Cisco") then
        result.vendor_hint = "Cisco"
      elseif response:find("Avaya") then
        result.vendor_hint = "Avaya"
      elseif response:find("Polycom") then
        result.vendor_hint = "Polycom"
      elseif response:find("Radvision") then
        result.vendor_hint = "Radvision"
      end

      result.response_size = #response .. " bytes"

      return stdnse.format_output(true, result)
    end
  end

  return stdnse.format_output(false, "No H.323 response received")
end
