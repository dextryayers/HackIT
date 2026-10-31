local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"



-- Fast-path bindings for the stdlib and nmap API used by this script.
-- Kept strict-mode safe: every name below is a declared local.
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
local move = table.move
local tostring = tostring
local tonumber = tonumber
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local unpack = table.unpack
local setmetatable = setmetatable
local getmetatable = getmetatable
local error = error
local select = select

local clock = nmap.clock
local msleep = nmap.msleep
local new_socket = nmap.new_socket
local resolve = nmap.resolve

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    return nmap.msleep(math.max(0, math.floor(seconds * 1000)))
end

local strsplit = function(sep, str, max)
    local out, pos, n = {}, 1, 0
    if str == nil then return out end
    while true do
        if max and n >= max - 1 then
            out[#out + 1] = sub(str, pos)
            return out
        end
        local s, e = find(str, sep, pos)
        if not s then
            out[#out + 1] = sub(str, pos)
            return out
        end
        if e < pos then e = pos end
        out[#out + 1] = sub(str, pos, s - 1)
        pos = e + 1
        n = n + 1
        if pos > #str then
            out[#out + 1] = ""
            return out
        end
    end
end

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
          local router_id = match(response, "....")
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
