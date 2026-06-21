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
      if response:sub(1, 4) == "AMQP" then
          insert(result, "AMQP broker detected")
      end
      if #response >= 7 then
          local proto = response:sub(5, 7)
          insert(result, ("Protocol version: %d.%d.%d"):format(proto:byte(1), proto:byte(2), proto:byte(3)))
      end
      socket:send(amqp_start_ok())
      status, response = socket:receive_bytes(1)
      if status and #response > 0 then
          insert(result, ("AMQP connection established (%d bytes)"):format(#response))
          local properties = response:match("product[^\x00]*")
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
