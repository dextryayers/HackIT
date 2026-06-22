local stdnse = require "stdnse"
local nmap = require "nmap"
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

description = [[Tests MSSQL accounts using user-provided credentials. No hardcoded credentials.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

local function load_list(arg_names)
  local val = stdnse.get_script_args(arg_names)
  if not val or val == "" then return {} end
  if byte(val) == 47 then
    local f, err = io.open(val, "r")
    if f then
      local lines = {}
      for line in f:lines() do
        line = gsub(line, "^%s+", ""):gsub("%s+$", "")
        if line ~= "" and byte(line) ~= 35 then insert(lines, line) end
      end
      f:close()
      return lines
    end
  elseif find(val, "\n") then
    local lines = {}
    for line in gmatch(val, "[^\n]+") do
      line = gsub(line, "^%s+", ""):gsub("%s+$", "")
      if line ~= "" and byte(line) ~= 35 then insert(lines, line) end
    end
    return lines
  end
  local items = {}
  for item in gmatch(val, "[^,]+") do
    item = gsub(item, "^%s+", ""):gsub("%s+$", "")
    if item ~= "" then insert(items, item) end
  end
  return items
end

local function le16(n) return char(n % 256, math.floor(n / 256) % 256) end
local function le32(n)
  return char(n % 256, math.floor(n / 256) % 256, math.floor(n / 65536) % 256, math.floor(n / 16777216) % 256)
end

local function build_prelogin()
  return char(
    0x02, 0x01, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
end

local function build_login7(user, pass, hostname)
  hostname = hostname or "localhost"
  local enc_pass = pass
  local hdr_size = 128
  local var_off = hdr_size
  local host_off, host_len = var_off, #hostname * 2
  var_off = var_off + host_len + 2
  local user_off, user_len = var_off, #user * 2
  var_off = var_off + user_len + 2
  local pass_off, pass_len = var_off, #enc_pass * 2
  var_off = var_off + pass_len + 2

  local total_len = var_off + 4
  local tds_pkt_len = 8 + total_len

  local function add_uni(str)
    local res = {}
    for i = 1, #str do insert(res, char(byte(str, i), 0)) end
    return concat(res) .. char(0, 0)
  end

  local hdr_parts = {
    le32(total_len), le32(0x07040000), le32(4096),
    le32(0), le32(0), le32(0),
    char(0x00, 0x00, 0x00, 0x00),
    le32(0), le32(0),
    le16(host_off) .. le16(host_len),
    le16(user_off) .. le16(user_len),
    le16(pass_off) .. le16(pass_len),
    le16(0) .. le16(0), le16(0) .. le16(0),
    rep(char(0), 44),
    le16(0) .. le16(0), le16(0) .. le16(0), le16(0) .. le16(0),
    le16(0) .. le16(0), le16(0) .. le16(0), le16(0) .. le16(0),
    le16(0) .. le16(0), le16(0) .. le16(0), le16(0) .. le16(0),
    le16(0) .. le16(0), le16(0) .. le16(0), le16(0) .. le16(0),
  }

  local body = concat(hdr_parts) .. add_uni(hostname) .. add_uni(user) .. add_uni(enc_pass)
  local tds_hdr = char(0x10, 0x01) .. le16(tds_pkt_len) .. le16(0) .. char(0x00, 0x00)
  return tds_hdr .. body
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 1433 or port.service == "ms-sql-s") end

action = function(host, port)
  local users = load_list({"ms-sql-empty-password.users", "users", "brute-mssql.users"})
  local passes = load_list({"ms-sql-empty-password.passwords", "passwords", "brute-mssql.passwords"})
  local timeout = tonumber(stdnse.get_script_args({"ms-sql-empty-password.timeout", "timeout"}) or 10)

  if #users == 0 then
    return format_output(false, "No users provided. Use ms-sql-empty-password.users script arg")
  end

  local result = output_table()
  local found_weak = false

  for _, u in ipairs(users) do
    if found_weak then break end
    for _, p in ipairs(passes) do
      if found_weak then break end
      local sock = new_socket()
      sock:set_timeout(timeout * 1000)
      local ok = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return end
        sock:send(build_prelogin())
        local _, pre_resp = sock:receive_buf("", 5000)
        if not pre_resp then sock:close(); return end
        sock:send(build_login7(u, p, host.ip or "localhost"))
        local _, login_resp = sock:receive_buf("", 5000)
        sock:close()
        if login_resp and #login_resp > 9 then
          if byte(login_resp, 9) == 0x01 then
            local token = byte(login_resp, 10)
            if token == 0xAD and (byte(login_resp, 14) == 0 or byte(login_resp, 14) == 1) then
              found_weak = true
              result.weak_accounts = result.weak_accounts or {}
              insert(result.weak_accounts, u .. "/" .. p)
            end
          end
        end
      end)
      if not ok then pcall(function() sock:close() end) end
    end
  end

  if found_weak then
    result.vulnerability = true
    result.severity = "CRITICAL"
    result.details = "MSSQL weak/default credentials detected"
    return result
  end
  return format_output(false, "No MSSQL weak credentials found")
end
