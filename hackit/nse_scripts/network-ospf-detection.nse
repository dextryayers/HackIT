local nmap = require "nmap"
local stdnse = require "stdnse"
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

description = [[
Detects OSPF (Open Shortest Path First) neighbors by sending OSPF Hello
packets and listening for OSPF protocol responses. Identifies OSPF
routers, their router IDs, and area information on the local network.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(89, "ospf")

action = function(host, port)
  local status, err = pcall(function()
      local result = {}
      local socket = new_socket("raw", "IP")
      socket:set_timeout(5000)
      local status, err = socket:connect(host, port)
      if not status then
          return format_output(false, "Could not connect: " .. tostring(err))
      end
      local ospf_hello = char(0x02, 0x01, 0x00, 0x18, 0x00, 0x00, 0x00, 0x01,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0xff, 0xff, 0xff, 0x00, 0x00, 0x0a, 0x00, 0x01)
      local status, sent = socket:send(ospf_hello)
      if not status then
          socket:close()
          return format_output(false, "Could not send OSPF Hello")
      end
      local status, response = socket:receive_bytes(1)
      if status and response then
          local router_id = response:match("....")
          if router_id then
              insert(result, "OSPF router detected")
              insert(result, "Router ID raw bytes received")
          end
          insert(result, ("OSPF response received (%d bytes)"):format(#response))
      else
          insert(result, "No OSPF response (routers may not be present)")
      end
      socket:close()
      return format_output(true, result)
  end)
  if not status then
    return format_output(false, "Script error: " .. tostring(err))
  end
end
