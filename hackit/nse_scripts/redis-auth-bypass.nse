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
