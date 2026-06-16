local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[Tests MSSQL accounts using user-provided credentials. No hardcoded credentials.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

local function load_list(arg_names)
  local val = stdnse.get_script_args(arg_names)
  if not val or val == "" then return {} end
  if val:sub(1, 1) == "/" then
    local f, err = io.open(val, "r")
    if f then
      local lines = {}
      for line in f:lines() do
        line = line:gsub("^%s+", ""):gsub("%s+$", "")
        if line ~= "" and line:sub(1, 1) ~= "#" then lines[#lines + 1] = line end
      end
      f:close()
      return lines
    end
  elseif val:find("\n") then
    local lines = {}
    for line in val:gmatch("[^\n]+") do
      line = line:gsub("^%s+", ""):gsub("%s+$", "")
      if line ~= "" and line:sub(1, 1) ~= "#" then lines[#lines + 1] = line end
    end
    return lines
  end
  local items = {}
  for item in val:gmatch("[^,]+") do
    item = item:gsub("^%s+", ""):gsub("%s+$", "")
    if item ~= "" then items[#items + 1] = item end
  end
  return items
end

local function le16(n) return string.char(n % 256, math.floor(n / 256) % 256) end
local function le32(n)
  return string.char(n % 256, math.floor(n / 256) % 256, math.floor(n / 65536) % 256, math.floor(n / 16777216) % 256)
end

local function build_prelogin()
  return string.char(
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
    for i = 1, #str do res[#res + 1] = string.char(str:byte(i), 0) end
    return table.concat(res) .. string.char(0, 0)
  end

  local hdr_parts = {
    le32(total_len), le32(0x07040000), le32(4096),
    le32(0), le32(0), le32(0),
    string.char(0x00, 0x00, 0x00, 0x00),
    le32(0), le32(0),
    le16(host_off) .. le16(host_len),
    le16(user_off) .. le16(user_len),
    le16(pass_off) .. le16(pass_len),
    le16(0) .. le16(0), le16(0) .. le16(0),
    string.rep(string.char(0), 44),
    le16(0) .. le16(0), le16(0) .. le16(0), le16(0) .. le16(0),
    le16(0) .. le16(0), le16(0) .. le16(0), le16(0) .. le16(0),
    le16(0) .. le16(0), le16(0) .. le16(0), le16(0) .. le16(0),
    le16(0) .. le16(0), le16(0) .. le16(0), le16(0) .. le16(0),
  }

  local body = table.concat(hdr_parts) .. add_uni(hostname) .. add_uni(user) .. add_uni(enc_pass)
  local tds_hdr = string.char(0x10, 0x01) .. le16(tds_pkt_len) .. le16(0) .. string.char(0x00, 0x00)
  return tds_hdr .. body
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 1433 or port.service == "ms-sql-s") end

action = function(host, port)
  local users = load_list({"ms-sql-empty-password.users", "users", "brute-mssql.users"})
  local passes = load_list({"ms-sql-empty-password.passwords", "passwords", "brute-mssql.passwords"})
  local timeout = tonumber(stdnse.get_script_args({"ms-sql-empty-password.timeout", "timeout"}) or 10)

  if #users == 0 then
    return stdnse.format_output(false, "No users provided. Use ms-sql-empty-password.users script arg")
  end

  local result = stdnse.output_table()
  local found_weak = false

  for _, u in ipairs(users) do
    if found_weak then break end
    for _, p in ipairs(passes) do
      if found_weak then break end
      local sock = nmap.new_socket()
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
          if login_resp:byte(9) == 0x01 then
            local token = login_resp:byte(10)
            if token == 0xAD and (login_resp:byte(14) == 0 or login_resp:byte(14) == 1) then
              found_weak = true
              result.weak_accounts = result.weak_accounts or {}
              table.insert(result.weak_accounts, u .. "/" .. p)
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
  return stdnse.format_output(false, "No MSSQL weak credentials found")
end
