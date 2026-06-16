local stdnse = require "stdnse"
local nmap = require "nmap"
local os = require "os"

description = [[Attempts to brute-force Microsoft SQL Server credentials using TDS login authentication.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"brute", "intrusive"}

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

local function build_prelogin()
  local data = string.char(0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
  local hdr = string.char(
    0x02, 0x01, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
  return hdr
end

local function build_login7(user, pass, hostname)
  hostname = hostname or "localhost"
  local enc_pass = pass
  local hdr_size = 128
  local var_offset = hdr_size
  local host_off, host_len = var_offset, #hostname * 2
  var_offset = var_offset + host_len + 2
  local user_off, user_len = var_offset, #user * 2
  var_offset = var_offset + user_len + 2
  local pass_off, pass_len = var_offset, #enc_pass * 2
  var_offset = var_offset + pass_len + 2
  local app_off, app_len = var_offset, 0
  var_offset = var_offset + app_len + 2
  local srv_off, srv_len = var_offset, 0
  var_offset = var_offset + srv_len + 2

  local total_len = var_offset + 4
  local tds_pkt_len = 8 + total_len

  local function le16(n) return string.char(n % 256, math.floor(n / 256) % 256) end
  local function le32(n)
    return string.char(n % 256, math.floor(n / 256) % 256, math.floor(n / 65536) % 256, math.floor(n / 16777216) % 256)
  end

  local hdr = {}
  hdr[1] = le32(total_len)
  hdr[2] = le32(0x07040000)
  hdr[3] = le32(4096)
  hdr[4] = le32(0)
  hdr[5] = le32(0)
  hdr[6] = le32(0)
  hdr[7] = string.char(0x00, 0x00, 0x00, 0x00)
  hdr[8] = le32(0)
  hdr[9] = le32(0)
  hdr[10] = le16(host_off) .. le16(host_len)
  hdr[11] = le16(user_off) .. le16(user_len)
  hdr[12] = le16(pass_off) .. le16(pass_len)
  hdr[13] = le16(app_off) .. le16(app_len)
  hdr[14] = le16(srv_off) .. le16(srv_len)
  hdr[15] = string.rep(string.char(0), 44)
  hdr[16] = le16(0) .. le16(0)
  hdr[17] = le16(0) .. le16(0)
  hdr[18] = le16(0) .. le16(0)
  hdr[19] = le16(0) .. le16(0)
  hdr[20] = le16(0) .. le16(0)
  hdr[21] = le16(0) .. le16(0)
  hdr[22] = le16(0) .. le16(0)
  hdr[23] = le16(0) .. le16(0)
  hdr[24] = le16(0) .. le16(0)
  hdr[25] = le16(0) .. le16(0)
  hdr[26] = le16(0) .. le16(0)

  local var_data = {}
  local function add_uni(str)
    for i = 1, #str do
      var_data[#var_data + 1] = string.char(str:byte(i), 0)
    end
    var_data[#var_data + 1] = string.char(0, 0)
  end
  add_uni(hostname)
  add_uni(user)
  add_uni(enc_pass)
  if app_len > 0 then add_uni("") end
  if srv_len > 0 then add_uni("") end

  local body = table.concat(hdr) .. table.concat(var_data)
  local tds_hdr = string.char(0x10, 0x01) .. le16(tds_pkt_len) .. le16(0) .. string.char(0x00, 0x00)
  return tds_hdr .. body
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 1433 or port.number == 1434) end

action = function(host, port)
  local users = load_list({"brute-mssql.users", "users"})
  local passes = load_list({"brute-mssql.passwords", "passwords"})
  local delay = tonumber(stdnse.get_script_args({"brute-mssql.delay", "delay"}) or 100)
  local max_attempts = tonumber(stdnse.get_script_args({"brute-mssql.max_attempts", "max_attempts"}) or 1000)
  local timeout = tonumber(stdnse.get_script_args({"brute-mssql.timeout", "timeout"}) or 10)
  local stop_on_first = stdnse.get_script_args({"brute-mssql.stop_on_first", "stop_on_first"})
  if stop_on_first == nil or stop_on_first == "" then stop_on_first = true
  else stop_on_first = (stop_on_first:lower() == "true" or stop_on_first == "1") end

  if #users == 0 or #passes == 0 then
    return stdnse.format_output(false, "No credentials provided. Use brute-mssql.users and brute-mssql.passwords script args")
  end

  local start_time = os.time()
  local found = {}
  local attempts = 0
  local errors = 0
  local success_count = 0
  local stop = false

  for _, u in ipairs(users) do
    if stop then break end
    for _, p in ipairs(passes) do
      if stop or attempts >= max_attempts then break end
      local socket = nmap.new_socket()
      socket:set_timeout(timeout * 1000)
      local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then errors = errors + 1; return false end
        socket:send(build_prelogin())
        local _, pre_resp = socket:receive_buf("", 5000)
        if not pre_resp then socket:close(); errors = errors + 1; return false end
        local login_pkt = build_login7(u, p, host.ip or "localhost")
        socket:send(login_pkt)
        local _, login_resp = socket:receive_buf("", 5000)
        socket:close()
        if login_resp and #login_resp > 9 then
          if login_resp:byte(9) == 0x01 then
            local token = login_resp:byte(10)
            if token == 0xAD then
              if login_resp:byte(14) == 0 or login_resp:byte(14) == 1 then
                return true
              end
            end
          elseif login_resp:byte(8) == 0x04 or login_resp:byte(8) == 0x05 then
            return true
          end
          local ad_pos = login_resp:find(string.char(0xAD))
          if ad_pos and ad_pos + 4 <= #login_resp then
            if login_resp:byte(ad_pos + 4) == 0 then return true end
          end
        end
        return false
      end)
      if not ok then
        pcall(socket.close, socket)
        errors = errors + 1
      elseif result then
        success_count = success_count + 1
        found[#found + 1] = {user = u, password = p}
        if stop_on_first then stop = true end
      end
      attempts = attempts + 1
      if delay > 0 and not stop then stdnse.sleep(delay / 1000) end
    end
  end

  local elapsed = os.time() - start_time
  local out = stdnse.output_table()
  out.service = "MSSQL"
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
