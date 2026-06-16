local stdnse = require "stdnse"
local nmap = require "nmap"
local bin = require "bin"
local string = require "string"
local math = require "math"
local bit = require "bit"
local os = require "os"

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

  local packet = string.char(first_byte) .. "\x00\x00\x00\x00\x00\x00\x00" ..
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

  local first_byte = response:byte(1)
  info.leap_indicator_raw = bit.rshift(first_byte, 6)
  local leap_descs = { "No warning", "Last minute has 61 seconds", "Last minute has 59 seconds", "Alarm (not synchronized)" }
  info.leap_indicator = leap_descs[info.leap_indicator_raw + 1] or "Unknown"

  info.version = bit.rshift(bit.band(first_byte, 0x38), 3)
  info.mode = bit.band(first_byte, 0x07)
  info.mode_name = info.mode == 4 and "server" or string.format("mode_%d", info.mode)

  info.stratum = response:byte(2)
  if info.stratum == 0 then
    info.stratum_desc = "unspecified or invalid"
  elseif info.stratum == 1 then
    info.stratum_desc = "primary reference (stratum 1)"
  elseif info.stratum <= 15 then
    info.stratum_desc = string.format("secondary reference (stratum %d)", info.stratum)
  else
    info.stratum_desc = "unsynchronized"
  end

  info.poll_interval = response:byte(3)
  info.poll_seconds = 2 ^ info.poll_interval
  info.precision = response:byte(4)
  info.root_delay_raw = response:byte(5) * 256 + response:byte(6)
  info.root_delay_seconds = info.root_delay_raw / 65536
  info.root_dispersion_raw = response:byte(7) * 256 + response:byte(8)
  info.root_dispersion_seconds = info.root_dispersion_raw / 65536

  local ref_id_bytes = { response:byte(13), response:byte(14), response:byte(15), response:byte(16) }
  if info.stratum == 0 or info.stratum == 1 then
    local ref_chars = string.char(ref_id_bytes[1], ref_id_bytes[2], ref_id_bytes[3], ref_id_bytes[4])
    local ref_ids = {
      ["LOCL"] = "Local clock", ["GPS"] = "GPS", ["ACTS"] = "ACTS",
      ["NIST"] = "NIST", ["USNO"] = "USNO", ["PTB"] = "PTB",
      ["TDF"] = "TDF", ["DCF"] = "DCF", ["CHU"] = "CHU",
      ["WWV"] = "WWV", ["WWVH"] = "WWVH", ["GOES"] = "GOES",
      ["PPS"] = "Pulse Per Second", ["IRIG"] = "IRIG",
    }
    info.reference_id = ref_ids[ref_chars] or ref_chars
  else
    info.reference_id = string.format("%d.%d.%d.%d", ref_id_bytes[1], ref_id_bytes[2], ref_id_bytes[3], ref_id_bytes[4])
  end

  info.reference_id_raw = string.format("%02x%02x%02x%02x", ref_id_bytes[1], ref_id_bytes[2], ref_id_bytes[3], ref_id_bytes[4])

  local function ts_to_seconds(offset)
    if #response >= offset + 7 then
      local int_part = response:byte(offset) * 256 * 256 * 256 +
                       response:byte(offset + 1) * 256 * 256 +
                       response:byte(offset + 2) * 256 +
                       response:byte(offset + 3)
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
  local result = stdnse.output_table()

  for _, ver in ipairs({ 4, 3, 2, 1 }) do
    local socket = nmap.new_socket("udp")
    socket:set_timeout(8000)

    local ok, err = pcall(socket.connect, socket, host.ip, port.number)
    if not ok then
      pcall(socket.close, socket)
      if _ == 1 then
        return stdnse.format_output(false, "Could not connect: " .. tostring(err))
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
      result.precision = string.format("2^%d", info.precision)
      result.root_delay_seconds = info.root_delay_seconds
      result.root_dispersion_seconds = info.root_dispersion_seconds
      result.reference_id = info.reference_id

      return stdnse.format_output(true, result)
    end
  end

  return stdnse.format_output(false, "No NTP response received")
end
