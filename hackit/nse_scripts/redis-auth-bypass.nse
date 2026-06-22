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
Checks for Redis authentication bypass vulnerabilities. Attempts to connect to
Redis servers without authentication and execute the INFO command to extract
server information and configuration details.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"auth", "safe"}

portrule = shortport.port_or_service(6379, "redis")

action = function(host, port)
  local status, err = pcall(function()
      local result = {}
      local socket = new_socket()
      socket:set_timeout(5000)
      local status, err = socket:connect(host, port)
      if not status then
          return format_output(false, "Could not connect: " .. tostring(err))
      end
      socket:send("INFO\r\n")
      local status, response = socket:receive_bytes(1)
      if not status then
          socket:send("PING\r\n")
          status, response = socket:receive_bytes(1)
      end
      if not status then
          socket:close()
          return format_output(false, "No response from Redis")
      end
      if match(response, "+OK") or match(response, "redis_version") or match(response, "# Server") then
          insert(result, "Redis authentication is DISABLED - full access available")
          if match(response, "redis_version:([%d.]+)") then
              insert(result, "Redis version: " .. match(response, "redis_version:([%d.]+)"))
          end
          if match(response, "os:([^\r\n]+)") then
              insert(result, "OS: " .. match(response, "os:([^\r\n]+)"))
          end
      else
          insert(result, "Redis requires authentication (AUTH required)")
      end
      socket:close()
      return format_output(true, result)
  end)
  if not status then
    return format_output(false, "Script error: " .. tostring(err))
  end
end
