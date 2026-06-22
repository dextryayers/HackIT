local stdnse = require "stdnse"
local nmap = require "nmap"
local bin = require "bin"
local string = require "string"
local math = require "math"
local bit = require "bit"
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

description = [[Queries NTP monlist (MON_GETLIST) to detect NTP amplification potential. Enumerates recent client IPs, counts, and calculates amplification factor for DDoS assessment.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.protocol == "udp" and port.state == "open" and port.number == 123
end

local function build_ntp_monlist_request()
  local leap = 0
  local version = 2
  local mode = 7
  local first_byte = bit.lshift(leap, 6) + bit.lshift(version, 3) + mode

  local request = char(first_byte) .. char(0x00) .. rep("\x00", 46)
  return request
end

local function build_ntp_peers_request()
  local leap = 0
  local version = 2
  local mode = 7
  local first_byte = bit.lshift(leap, 6) + bit.lshift(version, 3) + mode
  return char(first_byte) .. char(0x02) .. rep("\x00", 46)
end

local function parse_ntp_monlist(response)
  local info = {}

  if #response < 48 then return info end

  local resp_mode = bit.band(byte(response, 1), 0x07)
  info.mode = resp_mode
  local modes = { [4] = "server", [5] = "broadcast", [6] = "client", [7] = "control" }
  info.mode_name = modes[resp_mode] or format("Mode %d", resp_mode)

  if resp_mode == 7 and #response > 48 then
    local entry_count = math.floor((#response - 48) / 24)
    info.monlist_supported = true
    info.entry_count = entry_count

    local clients = {}
    for i = 0, entry_count - 1 do
      local offset = 49 + i * 24
      if offset + 24 <= #response then
        local addr_bytes = { byte(response, offset + 8), byte(response, offset + 9),
                            byte(response, offset + 10), byte(response, offset + 11) }
        local ip = format("%d.%d.%d.%d", addr_bytes[1], addr_bytes[2], addr_bytes[3], addr_bytes[4])
        insert(clients, ip)
      end
    end
    info.recent_clients = clients
    info.unique_clients = #clients
    info.amplification_factor = math.floor(#response / 48)
    info.amplification_risk = info.amplification_factor > 10 and "HIGH" or "MEDIUM"

    local version_byte = byte(response, 1)
    info.version = bit.rshift(bit.band(version_byte, 0x38), 3)
  end

  return info
end

action = function(host, port)
  local result = output_table()

  for _, req_func in ipairs({ build_ntp_monlist_request, build_ntp_peers_request }) do
    local socket = new_socket("udp")
    socket:set_timeout(10000)

    local ok, err = pcall(socket.connect, socket, host.ip, port.number)
    if not ok then
      pcall(socket.close, socket)
      if _ == 1 then
        return format_output(false, "Could not connect: " .. tostring(err))
      end
      break
    end

    local request = req_func()
    local ok2 = pcall(socket.send, socket, request)
    if not ok2 then
      pcall(socket.close, socket)
      break
    end

    local ok3, response = pcall(socket.receive_from, 10)
    pcall(socket.close, socket)

    if ok3 and response and #response >= 48 then
      local info = parse_ntp_monlist(response)
      result.ntp_detected = true
      result.monlist_supported = info.monlist_supported

      if info.monlist_supported then
        result.entry_count = info.entry_count
        result.amplification_factor = info.amplification_factor
        result.amplification_risk = info.amplification_risk

        if info.entry_count and info.entry_count > 0 then
          result.recent_clients = info.recent_clients
          result.unique_clients = info.unique_clients
        end

        return format_output(true, result)
      else
        result.mode_name = info.mode_name
        result.version = info.version
        result.amplification_risk = "LOW"
        return format_output(true, result)
      end
    end
  end

  return format_output(false, "NTP monlist not available")
end
