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
Detects Spanning Tree Protocol (STP) BPDU (Bridge Protocol Data Units)
frames on the network. Attempts to identify STP-enabled switches by
capturing and analyzing BPDU frames for bridge IDs and root bridge info.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(0, "stp")

action = function(host, port)
  local status, err = pcall(function()
      local result = {}
      local socket = new_socket("raw", "IP")
      socket:set_timeout(3000)
      local status, err = socket:connect(host, port)
      if not status then
          return format_output(false, "Raw socket not available: " .. tostring(err))
      end
      local stp_conf_bpdu = char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
      local status, sent = socket:send(stp_conf_bpdu)
      if not status then
          socket:close()
          return format_output(false, "Could not send STP BPDU probe")
      end
      local status, response = socket:receive_bytes(1)
      if status and response then
          insert(result, "STP BPDU response received")
          if #response >= 35 then
              local protocol_id = (response:byte(1) * 256) + response:byte(2)
              local bpdu_type = response:byte(20)
              if protocol_id == 0 then
                  insert(result, "IEEE 802.1D STP BPDU detected")
                  if bpdu_type == 0x00 then
                      insert(result, "Configuration BPDU")
                  elseif bpdu_type == 0x80 then
                      insert(result, "TCN BPDU")
                  end
                  local root_id = ("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x"):format(
                      response:byte(21), response:byte(22), response:byte(23),
                      response:byte(24), response:byte(25), response:byte(26),
                      response:byte(27), response:byte(28))
                  insert(result, "Root bridge ID: " .. root_id)
              end
          end
      else
          insert(result, "No STP BPDU response received")
      end
      socket:close()
      return format_output(true, result)
  end)
  if not status then
    return format_output(false, "Script error: " .. tostring(err))
  end
end
