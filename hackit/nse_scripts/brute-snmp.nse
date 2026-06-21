local stdnse = require "stdnse"
local nmap = require "nmap"
local os = require "os"
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

description = [[Attempts to brute-force SNMP community strings using user-provided credential lists.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"brute", "intrusive"}

local function load_list(arg_names, default)
  local val = stdnse.get_script_args(arg_names) or default
  if not val or val == "" then return {} end
  local f, err = io.open(val, "r")
  if f then
    local lines = {}
    for line in f:lines() do
      line = line:gsub("^%s+", ""):gsub("%s+$", "")
      if line ~= "" and line:byte() ~= 35 then
        insert(lines, line)
      end
    end
    f:close()
    return lines
  end
  local items = {}
  for item in val:gmatch("[^,]+") do
    item = item:gsub("^%s+", ""):gsub("%s+$", "")
    if item ~= "" then insert(items, item) end
  end
  return items
end

local function ber_encode_length(len)
  if len < 128 then
    return char(len)
  end
  local bytes = {}
  local n = len
  while n > 0 do
    insert(bytes, 1, bit.band(n, 0xFF))
    n = bit.rshift(n, 8)
  end
  return char(bit.bor(0x80, #bytes)) .. char(unpack(bytes))
end

local function ber_encode_integer(val)
  local bytes = {}
  local negative = val < 0
  if negative then val = val + 256 end
  local n = math.abs(val)
  while n > 0 do
    insert(bytes, 1, bit.band(n, 0xFF))
    n = bit.rshift(n, 8)
  end
  if #bytes == 0 then bytes = {0} end
  if negative then
    for i = 1, #bytes do bytes[i] = bit.bnot(bytes[i]) end
    for i = #bytes, 1, -1 do
      bytes[i] = bytes[i] + 1
      if bytes[i] <= 0xFF then break end
      bytes[i] = 0
    end
  end
  return char(0x02) .. ber_encode_length(#bytes) .. char(unpack(bytes))
end

local function ber_encode_octet_string(s)
  return char(0x04) .. ber_encode_length(#s) .. s
end

local function ber_encode_sequence(contents)
  return char(0x30) .. ber_encode_length(#contents) .. contents
end

local function ber_encode_null()
  return char(0x05, 0x00)
end

local function build_snmp_packet(community, req_id)
  local version = ber_encode_integer(0)
  local community_enc = ber_encode_octet_string(community)
  local pdu_contents = ber_encode_integer(req_id)
    .. ber_encode_integer(0)
    .. ber_encode_integer(0)
    .. ber_encode_sequence(
      ber_encode_sequence(
        ber_encode_octet_string(char(0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00))
        .. ber_encode_null()
      )
    )
  local get_request_pdu = char(0xa0) .. ber_encode_length(#pdu_contents) .. pdu_contents
  local whole_msg = ber_encode_sequence(version .. community_enc .. get_request_pdu)
  return whole_msg
end

portrule = function(host, port) return port.protocol == "udp" and port.state == "open" and port.number == 161 end

action = function(host, port)
  local communities = load_list({"brute-snmp.communities", "communities", "brute-snmp.passwords", "passwords"}, "public,private")
  local delay = tonumber(stdnse.get_script_args({"brute-snmp.delay", "delay"}) or 100)
  local max_attempts = tonumber(stdnse.get_script_args({"brute-snmp.max_attempts", "max_attempts"}) or 1000)
  local timeout = tonumber(stdnse.get_script_args({"brute-snmp.timeout", "timeout"}) or 10)
  local stop_on_first = stdnse.get_script_args({"brute-snmp.stop_on_first", "stop_on_first"})
  if stop_on_first == nil or stop_on_first == "" then stop_on_first = true
  else stop_on_first = (stop_on_first:lower() == "true" or stop_on_first == "1") end

  local start_time = os.time()
  local found = {}
  local attempts = 0
  local errors = 0
  local success_count = 0
  local stop = false

  for _, community in ipairs(communities) do
    if stop or attempts >= max_attempts then break end
    local socket = new_socket("udp")
    socket:set_timeout(timeout * 1000)
    local req_id = math.random(10000, 99999)
    local ok, result = pcall(function()
      local status, err = socket:connect(host, port, "udp")
      if not status then errors = errors + 1; return false end
      local pkt = build_snmp_packet(community, req_id)
      socket:send(pkt)
      local resp = socket:receive_bytes(1)
      socket:close()
      if resp and #resp > 10 then
        if resp:byte(1) == 0x30 then
          return true
        end
      end
      return false
    end)
    if not ok then
      pcall(socket.close, socket)
    end
    if result then
      success_count = success_count + 1
      insert(found, {community = community})
      if stop_on_first then stop = true end
    end
    attempts = attempts + 1
    if delay > 0 and not stop then sleep(delay / 1000) end
  end

  local elapsed = os.time() - start_time
  local out = output_table()
  out.service = "SNMP"
  out.port = port.number
  out.attempts = attempts
  out.success_count = success_count
  out.time_taken = elapsed .. "s"
  if #found > 0 then
    out.status = "VULNERABLE"
    out.found_credentials = found
  else
    out.status = "SECURE"
  end
  if errors > 0 then out.errors = errors end
  return out
end
