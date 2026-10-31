local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
-- Lua 5.4 has no "bit" module; this is a 32-bit compatible replacement.
local bit = (function()
    local floor = math.floor
    local function toint(x) return floor(x) & 0xFFFFFFFF end
    local function fold(fn, a, ...)
        local r = toint(a)
        for i = 1, select("#", ...) do
            r = toint(fn(r, select(i, ...)))
        end
        return r
    end
    return {
        band = function(...) return fold(function(x, y) return x & y end, ...) end,
        bor = function(...) return fold(function(x, y) return x | y end, ...) end,
        bxor = function(...) return fold(function(x, y) return x ~ y end, ...) end,
        bnot = function(x) return (~toint(x)) & 0xFFFFFFFF end,
        lshift = function(x, n) return (toint(x) << (n & 31)) & 0xFFFFFFFF end,
        rshift = function(x, n) return toint(x) >> (n & 31) end,
        arshift = function(x, n) return toint(x) >> (n & 31) end,
        tobit = function(x) return toint(x) end,
        tohex = function(x) return format("%08x", toint(x)) end,
    }
end)()
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
