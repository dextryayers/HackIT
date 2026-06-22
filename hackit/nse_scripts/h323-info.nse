local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
local bit = require "bit"
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
    data = char(
      0x00, 0x28, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00,
      0x00, 0x78, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ),
  },
  {
    name = "LRQ",
    data = char(
      0x00, 0x2a, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00,
      0x00, 0x79, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ),
  },
}

action = function(host, port)
  local result = output_table()

  for _, probe in ipairs(ras_discovery_packets) do
    local socket = new_socket()
    socket:set_timeout(5000)

    local ok, err = pcall(socket.connect, socket, host.ip, port.number)
    if not ok then
      socket:close()
      return format_output(false, "Failed to connect: " .. tostring(err))
    end

    local ok2, serr = pcall(socket.send, socket, probe.data)
    if not ok2 then
      socket:close()
      if _ == 1 then
        return format_output(false, "Failed to send " .. probe.name)
      end
      break
    end

    local ok3, response = pcall(socket.receive_buf, socket, 1024, true)
    socket:close()

    if ok3 and response and #response >= 10 then
      result.h323_detected = true
      result.probe = probe.name

      if #response >= 5 then
        local msg_type = byte(response, 5)
        local msg_types = {
          [0x78] = "Gatekeeper Discovery Response (GCF)",
          [0x14] = "Registration Confirm (RCF)",
          [0x1e] = "Unregistration Confirm (UCF)",
          [0x0a] = "Admission Confirm (ACF)",
          [0x2d] = "Location Confirm (LCF)",
          [0x50] = "Service Control Session",
          [0x79] = "Location Request (LRQ)",
        }
        result.message_type = msg_types[msg_type] or format("Unknown (0x%02x)", msg_type)
      end

      local vendor = match(response, "H323%-[%w%-]+") or
                     match(response, "[%w]+%-Gatekeeper") or
                     match(response, "([%w]+)[^%w]Gatekeeper") or
                     match(response, "Cisco") or
                     match(response, "Avaya") or
                     match(response, "Radvision") or
                     match(response, "Polycom") or
                     match(response, "Vidyo")
      if vendor then
        result.vendor = vendor
      end

      local version = match(response, "%d+%.%d+%.%d+%.%d+") or match(response, "%d+%.%d+%.%d+")
      if version then
        result.version = version
      end

      local prefix = match(response, "(%d+%*?)") or match(response, "(%d+%.%d+)")
      if prefix then
        result.prefix_hint = prefix
      end

      if find(response, "Cisco") then
        result.vendor_hint = "Cisco"
      elseif find(response, "Avaya") then
        result.vendor_hint = "Avaya"
      elseif find(response, "Polycom") then
        result.vendor_hint = "Polycom"
      elseif find(response, "Radvision") then
        result.vendor_hint = "Radvision"
      end

      result.response_size = #response .. " bytes"

      return format_output(true, result)
    end
  end

  return format_output(false, "No H.323 response received")
end
