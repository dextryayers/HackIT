local stdnse = require "stdnse"
local nmap = require "nmap"
local openssl = require "openssl"

description = [[Tests MySQL accounts using user-provided credentials. No hardcoded credentials.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

local function hex_to_bin(s)
  return (s:gsub("..", function(cc) return string.char(tonumber(cc, 16)) end))
end

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

local function mysql_native_hash(password, salt)
  local stage1_hex = openssl.sha1(password)
  local stage1 = hex_to_bin(stage1_hex:lower())
  local stage2_hex = openssl.sha1(stage1)
  local stage2 = hex_to_bin(stage2_hex:lower())
  local stage3_hex = openssl.sha1(salt .. stage2)
  local stage3 = hex_to_bin(stage3_hex:lower())
  local result = {}
  for i = 1, 20 do
    result[i] = string.char(string.byte(stage1, i) ~ string.byte(stage3, i))
  end
  return table.concat(result)
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 3306 or port.service == "mysql") end

action = function(host, port)
  local users = load_list({"mysql-empty-password.users", "users"})
  local passes = load_list({"mysql-empty-password.passwords", "passwords"})
  local timeout = tonumber(stdnse.get_script_args({"mysql-empty-password.timeout", "timeout"}) or 10)

  if #users == 0 then users = load_list({"mysql-empty-password.users", "users", "brute-mysql.users"}) end
  if #passes == 0 then passes = load_list({"mysql-empty-password.passwords", "passwords", "brute-mysql.passwords"}) end

  if #users == 0 then
    return stdnse.format_output(false, "No users provided. Use mysql-empty-password.users script arg")
  end

  local result = stdnse.output_table()
  local found = false

  for _, u in ipairs(users) do
    if found then break end
    for _, p in ipairs(passes) do
      if found then break end
      local sock = nmap.new_socket()
      sock:set_timeout(timeout * 1000)
      local ok = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return end
        local hb = sock:receive_bytes(128)
        if not hb or #hb < 5 then sock:close(); return end
        local sv = ""
        local pos = 2
        while pos <= #hb do
          local b = hb:byte(pos)
          if b == 0 then pos = pos + 1; break end
          sv = sv .. string.char(b)
          pos = pos + 1
        end
        if not result.version then result.version = sv end
        pos = pos + 4
        local part1 = hb:sub(pos, pos + 7); pos = pos + 8
        pos = pos + 9
        local auth_len = hb:byte(pos) or 20; pos = pos + 1
        pos = pos + 10
        local part2_len = auth_len - 8; if part2_len < 0 then part2_len = 12 end
        local part2 = hb:sub(pos, pos + part2_len - 1)
        local salt = part1 .. part2
        local auth_response = mysql_native_hash(p, salt)
        local client_caps = 0x0a285

        local function b3(n) return math.floor(n / 16777216) % 256 end
        local function b2(n) return math.floor(n / 65536) % 256 end
        local function b1(n) return math.floor(n / 256) % 256 end
        local caps_bin = string.char(client_caps % 256, b1(client_caps), b2(client_caps), b3(client_caps))
        local body = caps_bin .. string.char(255, 255, 255, 0) .. string.char(33) .. string.rep(string.char(0), 23)
          .. u .. string.char(0) .. string.char(#auth_response) .. auth_response .. "mysql_native_password" .. string.char(0)

        local pkt = string.char(#body % 256, math.floor(#body / 256) % 256, math.floor(#body / 65536) % 256, 1) .. body
        sock:send(pkt)
        local rh = sock:receive_bytes(4)
        if rh then
          local rl = string.byte(rh, 1) + string.byte(rh, 2) * 256 + string.byte(rh, 3) * 65536
          local rb = rl > 0 and sock:receive_bytes(rl) or ""
          local ok_resp = rb and rb:byte(1) == 0x00
          if ok_resp then found = true end
        end
        sock:close()
      end)
      if not ok then pcall(function() sock:close() end) end
    end
  end

  if found then
    result.vulnerability = true
    result.severity = "CRITICAL"
    result.details = "MySQL weak/default credentials found"
    return result
  end
  if result.version then
    result.vulnerability = false
    result.details = "No weak credentials found"
    return result
  end
  return stdnse.format_output(false, "Could not test MySQL credentials")
end
