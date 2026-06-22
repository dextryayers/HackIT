local stdnse = require "stdnse"
local nmap = require "nmap"
local bin = require "bin"
local string = require "string"
local math = require "math"
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

description = [[Detects BGP version by sending an OPEN message to the target. Extracts remote AS number, BGP version, hold time, router ID, and optional parameters from the BGP OPEN response.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and port.number == 179
end

local function bgp_open_message(asn, hold_time, bgp_id)
  local marker = rep(char(0xff), 16)
  local length = 29
  local type = 1
  local version = 4
  local my_as = bin.pack(">i", asn):sub(3, 4)
  local hold = bin.pack(">i", hold_time):sub(3, 4)
  local id_bytes = {}
  for octet in gmatch(bgp_id or "1.2.3.4", "%d+") do
    insert(id_bytes, char(tonumber(octet)))
  end
  local bgp_id_str = concat(id_bytes)
  local opt_param_len = char(0)
  local header = marker .. bin.pack(">i", length):sub(3, 4) .. char(type)
  local body = char(version) .. my_as .. hold .. bgp_id_str .. opt_param_len
  return header .. body
end

local function parse_bgp_open(response)
  local info = {}
  if #response >= 19 then
    local type_byte = byte(response, 19)
    info.message_type = type_byte
    local msg_types = { [1] = "OPEN", [2] = "OPEN", [3] = "NOTIFICATION", [4] = "KEEPALIVE" }
    info.message_name = msg_types[type_byte] or format("Unknown (%d)", type_byte)

    if type_byte == 2 and #response >= 29 then
      info.bgp_version = byte(response, 20)
      info.remote_as = byte(response, 21) * 256 + byte(response, 22)
      info.hold_time = byte(response, 23) * 256 + byte(response, 24)

      if byte(response, 25) and byte(response, 26) and byte(response, 27) and byte(response, 28) then
        info.router_id = format("%d.%d.%d.%d", byte(response, 25), byte(response, 26), byte(response, 27), byte(response, 28))
      end

      local opt_len = byte(response, 29)
      if opt_len and opt_len > 0 and #response >= 29 + opt_len then
        info.optional_parameters_present = true
        info.optional_parameters_length = opt_len
      end

    elseif type_byte == 3 and #response >= 21 then
      info.error_code = byte(response, 20)
      info.error_subcode = byte(response, 21)
      local error_codes = {
        [1] = "Message Header Error",
        [2] = "OPEN Message Error",
        [3] = "UPDATE Message Error",
        [4] = "Hold Timer Expired",
        [5] = "FSM Error",
        [6] = "Cease",
      }
      info.error_name = error_codes[info.error_code] or "Unknown"
    end
  end
  return info
end

action = function(host, port)
  local result = output_table()
  local socket = new_socket()
  socket:set_timeout(10000)

  local ok, err = pcall(socket.connect, socket, host.ip, port.number)
  if not ok then
    return format_output(false, "Could not connect to BGP port: " .. tostring(err))
  end

  local open_msg = bgp_open_message(64512, 90, host.ip or "1.2.3.4")
  local ok2, serr = pcall(socket.send, socket, open_msg)
  if not ok2 then
    socket:close()
    return format_output(false, "Failed to send BGP OPEN: " .. tostring(serr))
  end

  local ok3, response = pcall(socket.receive_buf, socket, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", 10)
  socket:close()

  if not ok3 or not response or #response < 19 then
    return format_output(false, "No BGP OPEN response received")
  end

  local bgp_info = parse_bgp_open(response)
  result.bgp_detected = true
  result.bgp_version = bgp_info.bgp_version
  result.remote_as = bgp_info.remote_as
  result.hold_time_seconds = bgp_info.hold_time
  result.router_id = bgp_info.router_id

  if bgp_info.error_code then
    result.notification = true
    result.error_code = bgp_info.error_code
    result.error_subcode = bgp_info.error_subcode
    result.error_name = bgp_info.error_name
    result.peer_rejected = true
  end

  if bgp_info.optional_parameters_present then
    result.has_optional_parameters = true
  end

  result.response_size = #response

  return format_output(true, result)
end
