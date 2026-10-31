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
Retrieves AMQP (Advanced Message Queuing Protocol) broker information
including server properties, capabilities, and authentication mechanisms.
Connects to RabbitMQ and other AMQP-compliant message brokers and
extracts version, platform, and product information.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(5672, "amqp")

local function amqp_protocol_header()
    return "AMQP\x00\x00\x09\x01"
end

local function amqp_start_ok()
    local client_properties = {
        {type = "long-str", key = "\x00product", value = "Nmap NSE"},
        {type = "long-str", key = "\x00version", value = "1.0"},
        {type = "long-str", key = "\x00platform", value = "NSE"},
        {type = "long-str", key = "\x00copyright", value = "HackIT"},
        {type = "long-str", key = "\x00information", value = "AMQP Discovery"},
    }
    local payload = char(0x00, 0x00, 0x00, 0x00)
    for _, prop in ipairs(client_properties) do
        if prop.type == "long-str" then
            payload = payload .. char(0x53) .. char(0x00, 0x00, 0x00, #prop.key) .. prop.key
            payload = payload .. char(0x00, 0x00, 0x00, #prop.value) .. prop.value
        end
    end
    local mechanism = "PLAIN"
    local response = char(0x00) .. "guest" .. char(0x00) .. "guest"
    payload = payload
        .. char(0x00, 0x00, 0x00, #mechanism) .. mechanism
        .. char(0x00, 0x00, 0x00, #response) .. response
    local frame = char(0x01, 0x00, 0x00, 0x00, 0x00, 0x00)
    frame = frame .. char(#payload >> 24, (#payload >> 16) & 0xff, (#payload >> 8) & 0xff, #payload & 0xff)
    frame = frame .. payload .. char(0xce)
    return frame
end

action = function(host, port)
  local status, err = pcall(function()
      local result = {}
      local socket = new_socket()
      socket:set_timeout(5000)
      local status, err = socket:connect(host, port)
      if not status then
          return format_output(false, "Could not connect: " .. tostring(err))
      end
      socket:send(amqp_protocol_header())
      local status, response = socket:receive_bytes(1)
      if not status then
          socket:close()
          return format_output(false, "No AMQP response")
      end
      if sub(response, 1, 4) == "AMQP" then
          insert(result, "AMQP broker detected")
      end
      if #response >= 7 then
          local proto = sub(response, 5, 7)
          insert(result, ("Protocol version: %d.%d.%d"):format(byte(proto, 1), byte(proto, 2), byte(proto, 3)))
      end
      socket:send(amqp_start_ok())
      status, response = socket:receive_bytes(1)
      if status and #response > 0 then
          insert(result, ("AMQP connection established (%d bytes)"):format(#response))
          local properties = match(response, "product[^\x00]*")
          if properties then
              insert(result, "Server product info present")
          end
      end
      socket:close()
      return format_output(true, result)
  end)
  if not status then
    return format_output(false, "Script error: " .. tostring(err))
  end
end
