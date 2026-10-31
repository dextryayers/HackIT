local stdnse = require "stdnse"
local nmap = require "nmap"
local bin = require "bin"
local string = require "string"
local math = require "math"
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
local os = require "os"
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

description = [[Detects OpenVPN services by probing the default port and parsing the handshake. Sends control channel packets and identifies OpenVPN version, opcodes, and data channel support from responses.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.protocol == "udp" and port.state == "open" and
    (port.number == 1194 or port.number == 443 or port.number == 1195)
end

local function build_openvpn_packet(opcode_val)
  local opcode = char(bit.lshift(opcode_val, 3))
  local peer_id = rep("\x00", 3)
  local hmac = rep("\x00", 20)
  local session_id = ""
  for i = 1, 8 do
    session_id = session_id .. char(math.random(0, 255))
  end
  local packet_id = rep("\x00", 8)
  local timestamp = bin.pack(">I", os.time())
  local payload = rep("\x00", 16)

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

  local first_byte = byte(response, 1)
  info.opcode = bit.rshift(first_byte, 3)
  info.key_id = bit.band(first_byte, 0x07)
  info.opcode_name = openvpn_opcodes[info.opcode] or format("Unknown (%d)", info.opcode)
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
  local result = output_table()

  local opcodes_to_test = {
    { name = "P_CONTROL_HARD_RESET_CLIENT_V1", opcode = 1 },
    { name = "P_CONTROL_HARD_RESET_CLIENT_V2", opcode = 8 },
    { name = "P_CONTROL_SOFT_RESET_V1", opcode = 3 },
  }

  for _, test in ipairs(opcodes_to_test) do
    local socket = new_socket("udp")
    socket:set_timeout(5000)

    local ok, err = pcall(socket.connect, socket, host.ip, port.number)
    if not ok then
      pcall(socket.close, socket)
      if _ == 1 then
        return format_output(false, "Could not connect: " .. tostring(err))
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

      return format_output(true, result)
    end
  end

  return format_output(false, "OpenVPN service not detected")
end
