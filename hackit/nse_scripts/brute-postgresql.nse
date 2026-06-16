local stdnse = require "stdnse"
local nmap = require "nmap"
local openssl = require "openssl"
local os = require "os"

description = [[Attempts to brute-force PostgreSQL credentials using MD5 password authentication.]]
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

local function le32(n)
  return string.char(n % 256, math.floor(n / 256) % 256, math.floor(n / 65536) % 256, math.floor(n / 16777216) % 256)
end

local function pg_md5_hash(user, password, salt)
  local inner = openssl.md5(password .. user)
  local inner_lc = inner:lower()
  local combined = inner_lc .. salt
  local outer = openssl.md5(combined)
  return "md5" .. outer:lower()
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.number == 5432 end

action = function(host, port)
  local users = load_list({"brute-postgresql.users", "users"})
  local passes = load_list({"brute-postgresql.passwords", "passwords"})
  local delay = tonumber(stdnse.get_script_args({"brute-postgresql.delay", "delay"}) or 100)
  local max_attempts = tonumber(stdnse.get_script_args({"brute-postgresql.max_attempts", "max_attempts"}) or 1000)
  local timeout = tonumber(stdnse.get_script_args({"brute-postgresql.timeout", "timeout"}) or 10)
  local stop_on_first = stdnse.get_script_args({"brute-postgresql.stop_on_first", "stop_on_first"})
  if stop_on_first == nil or stop_on_first == "" then stop_on_first = true
  else stop_on_first = (stop_on_first:lower() == "true" or stop_on_first == "1") end

  if #users == 0 or #passes == 0 then
    return stdnse.format_output(false, "No credentials provided. Use brute-postgresql.users and brute-postgresql.passwords script args")
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
      local socket = nmap.new_socket()
      socket:set_timeout(timeout * 1000)
      local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then errors = errors + 1; return false end

        local startup_len = 4 * 4 + 4 + #u + 1 + #("password") + 1 + 1 + 1
        local startup_data = string.char(0x00, 0x03, 0x00, 0x00)
          .. "user" .. string.char(0) .. u .. string.char(0)
          .. "database" .. string.char(0) .. u .. string.char(0)
          .. string.char(0)
        local startup_msg = le32(startup_len + 4) .. startup_data
        socket:send(startup_msg)

        local auth_resp = socket:receive_bytes(9)
        if not auth_resp then socket:close(); return false end

        if auth_resp:byte(1) == 0x52 then
          local auth_type = string.byte(auth_resp, 6) + string.byte(auth_resp, 7) * 256
            + string.byte(auth_resp, 8) * 65536 + string.byte(auth_resp, 9) * 16777216
          if auth_type == 0 then
            socket:close()
            return true
          elseif auth_type == 3 then
            local salt = auth_resp:sub(10, 13)
            if #salt < 4 then
              local rest = socket:receive_bytes(4 - #salt)
              if rest then salt = salt .. rest end
            end
            local pwhash = pg_md5_hash(u, p, salt)
            local pkt = "p" .. le32(4 + #pwhash) .. pwhash
            socket:send(pkt)
            local resp = socket:receive_bytes(5)
            socket:close()
            if resp and #resp >= 5 then
              if resp:byte(1) == 0x52 then
                local code = string.byte(resp, 6) + string.byte(resp, 7) * 256
                  + string.byte(resp, 8) * 65536 + string.byte(resp, 9) * 16777216
                if code == 0 then return true end
              end
            end
            return false
          elseif auth_type == 5 then
            local pkt = "p" .. le32(4 + #p) .. p
            socket:send(pkt)
            local resp = socket:receive_bytes(5)
            socket:close()
            if resp and #resp >= 5 and resp:byte(1) == 0x52 then
              local code = string.byte(resp, 6) + string.byte(resp, 7) * 256
                + string.byte(resp, 8) * 65536 + string.byte(resp, 9) * 16777216
              if code == 0 then return true end
            end
            return false
          end
        elseif auth_resp:byte(1) == 0x45 then
          socket:close()
          return false
        elseif auth_resp:byte(1) == 0x4e then
          socket:close()
          return false
        end
        socket:close()
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
  out.service = "PostgreSQL"
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
