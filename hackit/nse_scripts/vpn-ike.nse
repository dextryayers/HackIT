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

description = [[Detects IKE/IPsec VPN services by sending ISAKMP initiator cookies with multiple transforms. Extracts IKE version, exchange type, SA payload details, and proposal information from responses.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.protocol == "udp" and port.state == "open" and (port.number == 500 or port.number == 4500)
end

local function random_cookie_string(length)
  local result = ""
  for i = 1, length do
    result = result .. char(math.random(0, 255))
  end
  return result
end

local function build_isakmp_packet(transform_params)
  local init_cookie = transform_params and transform_params.cookie or random_cookie_string(8)
  local resp_cookie = rep("\x00", 8)
  local next_payload = transform_params and transform_params.next_payload or 5
  local version = char(0x10)
  local exchange_type = transform_params and transform_params.exchange_type or 2
  local flags = transform_params and transform_params.flags or char(0x00)
  local message_id = rep("\x00", 4)

  local isakmp_header = init_cookie .. resp_cookie .. char(next_payload) ..
                        version .. char(exchange_type) .. flags .. message_id

  local sa_payload = char(next_payload == 5 and 0 or 0, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

  local proposal_num = 1
  local proposal_payload = char(0x00, 0x00, 0x00, proposal_num, 0x01, 0x00, 0x00, 0x04)

  local transform_id = transform_params and transform_params.transform_id or 1
  local transform_payload = char(0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x04)

  local payload = sa_payload .. proposal_payload .. transform_payload
  local total_length = #isakmp_header + #payload
  local len_bytes = bin.pack(">I", total_length):sub(1, 4)
  isakmp_header = isakmp_header:sub(1, 24) .. len_bytes

  return isakmp_header .. payload
end

local function parse_ike_response(response)
  local info = {}
  if #response < 28 then return info end

  info.initiator_cookie = response:sub(1, 8)
  info.responder_cookie = response:sub(9, 16)
  info.next_payload = response:byte(17)
  local ver_byte = response:byte(18)
  info.major_version = bit.rshift(bit.band(ver_byte, 0xF0), 4)
  info.minor_version = bit.band(ver_byte, 0x0F)
  info.exchange_type = response:byte(20)

  local flags = response:byte(21)
  info.encryption_flag = bit.band(flags, 0x04) ~= 0
  info.commit_flag = bit.band(flags, 0x08) ~= 0
  info.authentication_flag = bit.band(flags, 0x10) ~= 0

  local payload_types = {
    [0] = "None", [1] = "SA", [2] = "Proposal", [3] = "Transform",
    [4] = "Key Exchange", [5] = "ID", [6] = "Certificate",
    [7] = "Certificate Request", [8] = "Hash", [9] = "Nonce",
    [10] = "Notify", [11] = "Delete", [12] = "Vendor ID",
    [13] = "Traffic Selector", [14] = "Configuration",
  }
  info.next_payload_name = payload_types[info.next_payload] or "Unknown"

  local exchange_types = {
    [0] = "None", [1] = "Base", [2] = "Identity Protection",
    [3] = "Auth Only", [4] = "Aggressive", [5] = "Informational",
  }
  info.exchange_type_name = exchange_types[info.exchange_type] or format("Unknown (%d)", info.exchange_type)

  return info
end

action = function(host, port)
  local result = output_table()
  local socket = new_socket("udp")
  socket:set_timeout(8000)

  local ok, err = pcall(socket.connect, socket, host.ip, port.number)
  if not ok then
    return format_output(false, "Could not connect: " .. tostring(err))
  end

  local cookie = random_cookie_string(8)
  local packet = build_isakmp_packet({ cookie = cookie })
  local ok2, serr = pcall(socket.send, socket, packet)
  if not ok2 then
    socket:close()
    return format_output(false, "Send failed: " .. tostring(serr))
  end

  local ok3, response = pcall(socket.receive_from, 10)
  socket:close()

  if not ok3 or not response or #response < 28 then
    return format_output(false, "No IKE response received (VPN may be filtering)")
  end

  local ike_info = parse_ike_response(response)
  result.ike_detected = true
  result.ike_version = format("%d.%d", ike_info.major_version, ike_info.minor_version)
  result.major_version = ike_info.major_version
  result.minor_version = ike_info.minor_version
  result.exchange_type = ike_info.exchange_type
  result.exchange_type_name = ike_info.exchange_type_name
  result.encryption_bit_set = ike_info.encryption_flag
  result.response_size = #response

  if ike_info.responder_cookie and ike_info.responder_cookie ~= rep("\x00", 8) then
    result.responder_cookie_present = true
  end

  return format_output(true, result)
end
