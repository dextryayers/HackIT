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

description = [[Checks for Oracle TNS (Transparent Network Substrate) listener service. Attempts to extract listener version, service information, instance details, and security settings via the TNS protocol with multiple probes.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "database"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and port.number == 1521
end

local function build_tns_packet(connect_data)
  local header = char(
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x2e,
    0x00, 0x00, 0x08, 0x00, 0x7f, 0xff, 0x7f, 0x08,
    0x00, 0x00, 0x00, 0x01
  )

  local payload = char(0x00, 0x00, 0x00, 0x3c) ..
    rep("\x00", 32) ..
    "(" .. connect_data .. ")"

  local total_len = #header + #payload
  header = sub(header, 1, 24) .. char(0x00, 0x00) ..
           char(bit.rshift(total_len, 8), bit.band(total_len, 0xFF)) ..
           sub(header, 29)

  return header .. payload
end

local tns_probes = {
  { name = "VERSION", data = "CONNECT_DATA=(COMMAND=version)" },
  { name = "SERVICES", data = "CONNECT_DATA=(COMMAND=services)" },
  { name = "STATUS", data = "CONNECT_DATA=(COMMAND=status)" },
  { name = "PING", data = "CONNECT_DATA=(COMMAND=ping)" },
  { name = "DESCRIPTION", data = "DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=))(ADDRESS=(PROTOCOL=tcp))" },
}

action = function(host, port)
  local result = output_table()
  local all_data = ""

  for _, probe in ipairs(tns_probes) do
    local socket = new_socket()
    socket:set_timeout(5000)

    local ok, err = pcall(socket.connect, socket, host.ip, port.number)
    if not ok then
      socket:close()
      if _ == 1 then
        return format_output(false, "Failed to connect: " .. tostring(err))
      end
      break
    end

    local pkt = build_tns_packet(probe.data)
    local ok2, send_err = pcall(socket.send, socket, pkt)
    if not ok2 then
      socket:close()
      break
    end

    local ok3, response = pcall(socket.receive_buf, socket, 2048, true)
    socket:close()

    if ok3 and response and #response > 4 then
      all_data = all_data .. response

      if match(response, "Oracle") or match(response, "TNS") then
        result.listener_detected = true
      end

      local version_match = match(response, "TNSLSNR.-%d+%.%d+%.%d+%.%d+")
        or match(response, "Version.-%d+%.%d+%.%d+%.%d+")
        or match(response, "(%d+%.%d+%.%d+%.%d+%.%d+)")
      if version_match and not result.version then
        result.version = version_match
      end

      local product = match(response, "PRODUCT%s*=%s*([%w%s]+)") or match(response, "PRODUCT:([%w%s]+)")
      if product and not result.product then
        result.product = gsub(product, "%s+$", "")
      end

      local services = {}
      for svc in response:gmatch("%(([A-Z][A-Z_]+)%s*=") do
        if not result[lower(svc)] then
          insert(services, svc)
        end
      end
      if #services > 4 then
        result.service_parameters = services
      end

      local instance = match(response, "INSTANCE_NAME%s*=%s*([%w_]+)")
        or match(response, "INST_NAME%s*=%s*([%w_]+)")
      if instance and not result.instance_name then
        result.instance_name = instance
      end

      local host_name = match(response, "HOST_NAME%s*=%s*([%w_%.%-]+)")
      if host_name and not result.host_name then
        result.host_name = host_name
      end

      local sec = match(response, "SECURITY[^)]*") or match(response, "SEC_PROTOCOL[^)]*")
      if sec and not result.security then
        result.security = sec
      end
    end
  end

  if not result.listener_detected then
    return format_output(false, "No TNS response received")
  end

  result.response_size = #all_data
  return format_output(true, result)
end
