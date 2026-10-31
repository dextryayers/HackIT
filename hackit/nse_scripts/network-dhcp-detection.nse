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
local msleep = function(ms)
    if stdnse and stdnse.sleep then
        return stdnse.sleep((ms or 0) / 1000)
    end
    if nmap.msleep then
        return nmap.msleep(ms or 0)
    end
    local deadline = nmap.clock() + (ms or 0) / 1000
    while nmap.clock() < deadline do end
    return true
end
local new_socket = nmap.new_socket
local resolve = nmap.resolve

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    if stdnse and stdnse.sleep then
        return stdnse.sleep(seconds)
    end
    if nmap.msleep then
        return nmap.msleep(math.max(0, math.floor((seconds or 0) * 1000)))
    end
    local deadline = nmap.clock() + (seconds or 0)
    while nmap.clock() < deadline do end
    return true
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
