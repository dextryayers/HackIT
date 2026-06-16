local stdnse = require "stdnse"
local nmap = require "nmap"
local bin = require "bin"
local string = require "string"
local math = require "math"
local bit = require "bit"
local os = require "os"

description = [[Detects OpenVPN services by probing the default port and parsing the handshake. Sends control channel packets and identifies OpenVPN version, opcodes, and data channel support from responses.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.protocol == "udp" and port.state == "open" and
    (port.number == 1194 or port.number == 443 or port.number == 1195)
end

local function build_openvpn_packet(opcode_val)
  local opcode = string.char(bit.lshift(opcode_val, 3))
  local peer_id = string.rep("\x00", 3)
  local hmac = string.rep("\x00", 20)
  local session_id = ""
  for i = 1, 8 do
    session_id = session_id .. string.char(math.random(0, 255))
  end
  local packet_id = string.rep("\x00", 8)
  local timestamp = bin.pack(">I", os.time())
  local payload = string.rep("\x00", 16)

  return opcode .. peer_id .. hmac .. session_id .. packet_id .. timestamp .. payload
end

local openvpn_opcodes = {
  [1] = "P_CONTROL_HARD_RESET_CLIENT_V1",
  [2] = "P_CONTROL_HARD_RESET_SERVER_V1",
  [3] = "P_CONTROL_SOFT_RESET_V1",
  [4] = "P_CONTROL_V1",
  [5] = "P_ACK_V1",
  [6] = "P_DATA_V1",
  [7] = "P_DATA_V1 (alt)",
  [8] = "P_CONTROL_HARD_RESET_CLIENT_V2",
  [9] = "P_CONTROL_HARD_RESET_SERVER_V2",
  [10] = "P_CONTROL_SOFT_RESET_V2",
  [11] = "P_CONTROL_V2",
  [12] = "P_ACK_V2",
  [13] = "P_DATA_V2",
  [14] = "P_HP_DATA_V2",
}

local function parse_openvpn_response(response)
  local info = {}
  if #response < 2 then return info end

  local first_byte = response:byte(1)
  info.opcode = bit.rshift(first_byte, 3)
  info.key_id = bit.band(first_byte, 0x07)
  info.opcode_name = openvpn_opcodes[info.opcode] or string.format("Unknown (%d)", info.opcode)
  info.packet_size = #response

  if #response >= 48 then
    info.hard_reset_style = info.opcode >= 8 and "v2" or "v1"
    info.has_hmac = true
    if #response >= 32 then
      info.has_session_id = true
    end
  end

  return info
end

action = function(host, port)
  local result = stdnse.output_table()

  local opcodes_to_test = {
    { name = "P_CONTROL_HARD_RESET_CLIENT_V1", opcode = 1 },
    { name = "P_CONTROL_HARD_RESET_CLIENT_V2", opcode = 8 },
    { name = "P_CONTROL_SOFT_RESET_V1", opcode = 3 },
  }

  for _, test in ipairs(opcodes_to_test) do
    local socket = nmap.new_socket("udp")
    socket:set_timeout(5000)

    local ok, err = pcall(socket.connect, socket, host.ip, port.number)
    if not ok then
      pcall(socket.close, socket)
      if _ == 1 then
        return stdnse.format_output(false, "Could not connect: " .. tostring(err))
      end
      break
    end

    local packet = build_openvpn_packet(test.opcode)
    local ok2 = pcall(socket.send, socket, packet)
    if not ok2 then
      pcall(socket.close, socket)
      break
    end

    local ok3, response = pcall(socket.receive_from, 10)
    pcall(socket.close, socket)

    if ok3 and response and #response >= 2 then
      local ovpn_info = parse_openvpn_response(response)
      result.openvpn_detected = true
      result.response_opcode = ovpn_info.opcode
      result.response_opcode_name = ovpn_info.opcode_name
      result.probe_sent = test.name
      result.hard_reset_style = ovpn_info.hard_reset_style
      result.packet_size = ovpn_info.packet_size
      result.has_session_id = ovpn_info.has_session_id
      result.has_hmac = ovpn_info.has_hmac

      if ovpn_info.opcode == 7 or ovpn_info.opcode == 13 then
        result.data_channel = true
      end

      if ovpn_info.opcode == 1 or ovpn_info.opcode == 2 or
         ovpn_info.opcode == 8 or ovpn_info.opcode == 9 then
        result.hard_reset_negotiation = true
      end

      return stdnse.format_output(true, result)
    end
  end

  return stdnse.format_output(false, "OpenVPN service not detected")
end
