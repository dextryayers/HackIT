local stdnse = require "stdnse"
local nmap = require "nmap"
local os = require "os"

description = [[Attempts to brute-force Redis AUTH credentials using the AUTH command.]]
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

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.number == 6379 end

action = function(host, port)
  local passes = load_list({"brute-redis.passwords", "passwords", "brute-redis.users", "users"})
  local delay = tonumber(stdnse.get_script_args({"brute-redis.delay", "delay"}) or 100)
  local max_attempts = tonumber(stdnse.get_script_args({"brute-redis.max_attempts", "max_attempts"}) or 1000)
  local timeout = tonumber(stdnse.get_script_args({"brute-redis.timeout", "timeout"}) or 10)
  local stop_on_first = stdnse.get_script_args({"brute-redis.stop_on_first", "stop_on_first"})
  if stop_on_first == nil or stop_on_first == "" then stop_on_first = true
  else stop_on_first = (stop_on_first:lower() == "true" or stop_on_first == "1") end

  if #passes == 0 then
    return stdnse.format_output(false, "No credentials provided. Use brute-redis.passwords or brute-redis.users script args")
  end

  local start_time = os.time()
  local found = {}
  local attempts = 0
  local errors = 0
  local success_count = 0
  local stop = false
  local server_version = nil

  local function try_auth(pass)
    local socket = nmap.new_socket()
    socket:set_timeout(timeout * 1000)
    local ok, result = pcall(function()
      local status, err = socket:connect(host, port)
      if not status then return false, nil end
      socket:send("AUTH " .. pass .. "\r\n")
      local resp = socket:receive_bytes(10)
      socket:close()
      if resp then
        if resp:find("+OK") then return true end
        if resp:find("-NOAUTH") then return false end
        if resp:find("-ERR") then return false end
      end
      return false
    end)
    if not ok then pcall(socket.close, socket) end
    return ok and result
  end

  local function check_noauth()
    local socket = nmap.new_socket()
    socket:set_timeout(3000)
    local ok, result = pcall(function()
      local status, err = socket:connect(host, port)
      if not status then return false end
      local resp = socket:receive_bytes(10)
      if resp then
        socket:send("PING\r\n")
        local pong = socket:receive_bytes(10)
        socket:close()
        if not resp:find("-NOAUTH") and not resp:find("-ERR") then return true end
        if pong and pong:find("+PONG") then return true end
      end
      socket:close()
      return false
    end)
    if not ok then pcall(socket.close, socket) end
    return ok and result
  end

  if check_noauth() then
    success_count = 1
    found[#found + 1] = {password = "(no password required)"}
    stop = true
  end

  if not stop then
    for _, p in ipairs(passes) do
      if stop or attempts >= max_attempts then break end
      local result = try_auth(p)
      if result then
        success_count = success_count + 1
        found[#found + 1] = {password = p}
        if stop_on_first then stop = true end
      elseif result == nil then
        errors = errors + 1
      end
      attempts = attempts + 1
      if delay > 0 and not stop then stdnse.sleep(delay / 1000) end
    end
  end

  local elapsed = os.time() - start_time
  local out = stdnse.output_table()
  out.service = "Redis"
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
