local stdnse = require "stdnse"
local nmap = require "nmap"
local bin = require "bin"
local string = require "string"
local math = require "math"
local bit = require "bit"
local os = require "os"
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

description = [[Retrieves NTP server information including version, stratum, timing details, reference clock, and synchronization state. Sends NTP mode 3 (client) requests to obtain full server response.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.protocol == "udp" and port.state == "open" and port.number == 123
end

local function build_ntp_request(version)
  local leap = 0
  local mode = 3
  local first_byte = bit.lshift(leap, 6) + bit.lshift(version, 3) + mode
  local originate_ts = bin.pack(">I", os.time()) .. "\x00\x00\x00\x00"

  local packet = char(first_byte) .. "\x00\x00\x00\x00\x00\x00\x00" ..
                 "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ..
                 "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ..
                 originate_ts ..
                 "\x00\x00\x00\x00\x00\x00\x00\x00" ..
                 "\x00\x00\x00\x00\x00\x00\x00\x00" ..
                 "\x00\x00\x00\x00\x00\x00\x00\x00" ..
                 "\x00\x00\x00\x00\x00\x00\x00\x00"
  return packet
end

local function parse_ntp_response(response)
  local info = {}
  if #response < 48 then return info end

  local first_byte = byte(response, 1)
  info.leap_indicator_raw = bit.rshift(first_byte, 6)
  local leap_descs = { "No warning", "Last minute has 61 seconds", "Last minute has 59 seconds", "Alarm (not synchronized)" }
  info.leap_indicator = leap_descs[info.leap_indicator_raw + 1] or "Unknown"

  info.version = bit.rshift(bit.band(first_byte, 0x38), 3)
  info.mode = bit.band(first_byte, 0x07)
  info.mode_name = info.mode == 4 and "server" or format("mode_%d", info.mode)

  info.stratum = byte(response, 2)
  if info.stratum == 0 then
    info.stratum_desc = "unspecified or invalid"
  elseif info.stratum == 1 then
    info.stratum_desc = "primary reference (stratum 1)"
  elseif info.stratum <= 15 then
    info.stratum_desc = format("secondary reference (stratum %d)", info.stratum)
  else
    info.stratum_desc = "unsynchronized"
  end

  info.poll_interval = byte(response, 3)
  info.poll_seconds = 2 ^ info.poll_interval
  info.precision = byte(response, 4)
  info.root_delay_raw = byte(response, 5) * 256 + byte(response, 6)
  info.root_delay_seconds = info.root_delay_raw / 65536
  info.root_dispersion_raw = byte(response, 7) * 256 + byte(response, 8)
  info.root_dispersion_seconds = info.root_dispersion_raw / 65536

  local ref_id_bytes = { byte(response, 13), byte(response, 14), byte(response, 15), byte(response, 16) }
  if info.stratum == 0 or info.stratum == 1 then
    local ref_chars = char(ref_id_bytes[1], ref_id_bytes[2], ref_id_bytes[3], ref_id_bytes[4])
    local ref_ids = {
      ["LOCL"] = "Local clock", ["GPS"] = "GPS", ["ACTS"] = "ACTS",
      ["NIST"] = "NIST", ["USNO"] = "USNO", ["PTB"] = "PTB",
      ["TDF"] = "TDF", ["DCF"] = "DCF", ["CHU"] = "CHU",
      ["WWV"] = "WWV", ["WWVH"] = "WWVH", ["GOES"] = "GOES",
      ["PPS"] = "Pulse Per Second", ["IRIG"] = "IRIG",
    }
    info.reference_id = ref_ids[ref_chars] or ref_chars
  else
    info.reference_id = format("%d.%d.%d.%d", ref_id_bytes[1], ref_id_bytes[2], ref_id_bytes[3], ref_id_bytes[4])
  end

  info.reference_id_raw = format("%02x%02x%02x%02x", ref_id_bytes[1], ref_id_bytes[2], ref_id_bytes[3], ref_id_bytes[4])

  local function ts_to_seconds(offset)
    if #response >= offset + 7 then
      local int_part = byte(response, offset) * 256 * 256 * 256 +
                       byte(response, offset + 1) * 256 * 256 +
                       byte(response, offset + 2) * 256 +
                       byte(response, offset + 3)
      return int_part
    end
    return nil
  end

  info.reference_timestamp = ts_to_seconds(17)
  info.originate_timestamp = ts_to_seconds(25)
  info.receive_timestamp = ts_to_seconds(33)
  info.transmit_timestamp = ts_to_seconds(41)

  return info
end

action = function(host, port)
  local result = output_table()

  for _, ver in ipairs({ 4, 3, 2, 1 }) do
    local socket = new_socket("udp")
    socket:set_timeout(8000)

    local ok, err = pcall(socket.connect, socket, host.ip, port.number)
    if not ok then
      pcall(socket.close, socket)
      if _ == 1 then
        return format_output(false, "Could not connect: " .. tostring(err))
      end
      break
    end

    local request = build_ntp_request(ver)
    local ok2 = pcall(socket.send, socket, request)
    if not ok2 then
      pcall(socket.close, socket)
      break
    end

    local ok3, response = pcall(socket.receive_from, 10)
    pcall(socket.close, socket)

    if ok3 and response and #response >= 48 then
      local info = parse_ntp_response(response)
      result.ntp_detected = true
      result.version = info.version
      result.mode = info.mode_name
      result.leap_indicator = info.leap_indicator
      result.stratum = info.stratum
      result.stratum_desc = info.stratum_desc
      result.poll_interval_seconds = info.poll_seconds
      result.precision = format("2^%d", info.precision)
      result.root_delay_seconds = info.root_delay_seconds
      result.root_dispersion_seconds = info.root_dispersion_seconds
      result.reference_id = info.reference_id

      return format_output(true, result)
    end
  end

  return format_output(false, "No NTP response received")
end
