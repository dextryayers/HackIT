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
Discovers DHCP servers on the local network by sending DHCP DISCOVER
broadcast messages and listening for DHCP OFFER responses. Extracts
DHCP server information including offered IP addresses and server IDs.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(67, "dhcp")

local function build_dhcp_discover()
    local xid = char(0x00, 0x00, 0x00, 0x01)
    local dhcp = char(0x01, 0x01, 0x06, 0x00)
        .. xid
        .. char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        .. char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        .. char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        .. char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        .. char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        .. char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        .. char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        .. char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        .. "HACKIT"
        .. rep("\x00", 219)
        .. char(0x63, 0x82, 0x53, 0x63)
        .. char(0x35, 0x01, 0x01)
        .. char(0x37, 0x04, 0x01, 0x03, 0x06, 0x0f)
        .. char(0xff)
    return dhcp
end

action = function(host, port)
  local status, err = pcall(function()
      local result = {}
      local socket = new_socket("udp")
      socket:set_timeout(5000)
      socket:set_option("broadcast", true)
      socket:bind(nil, 68)
      local dhcp_discover = build_dhcp_discover()
      local status, err = socket:send(dhcp_discover, "255.255.255.255", 67)
      if not status then
          return format_output(false, "Could not send DHCP DISCOVER: " .. tostring(err))
      end
      repeat
          local status, data, rhost, rport = socket:receive()
          if status and data then
              local msg_type = byte(data, 242)
              if msg_type == 2 then
                  local server_id = ("%d.%d.%d.%d"):format(byte(data, 244), byte(data, 245), byte(data, 246), byte(data, 247))
                  local yiaddr = ("%d.%d.%d.%d"):format(byte(data, 16), byte(data, 17), byte(data, 18), byte(data, 19))
                  insert(result, ("DHCP OFFER from %s (server ID: %s, offered IP: %s)"):format(rhost, server_id, yiaddr))
              end
          end
      until not status
      socket:close()
      if #result == 0 then
          insert(result, "No DHCP servers responded")
      end
      return format_output(true, result)
  end)
  if not status then
    return format_output(false, "Script error: " .. tostring(err))
  end
end
