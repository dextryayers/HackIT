local stdnse = require "stdnse"
local nmap = require "nmap"
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

description = [[Attempts to brute-force HTTP Form-based authentication using user-provided credential lists.]]
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

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 80 or port.number == 443) end

action = function(host, port)
  local users = load_list({"brute-http-form.users", "users"}, "root,admin")
  local passes = load_list({"brute-http-form.passwords", "passwords"}, "password,12345,admin")
  local delay = tonumber(stdnse.get_script_args({"brute-http-form.delay", "delay"}) or 100)
  local max_attempts = tonumber(stdnse.get_script_args({"brute-http-form.max_attempts", "max_attempts"}) or 1000)
  local timeout = tonumber(stdnse.get_script_args({"brute-http-form.timeout", "timeout"}) or 10)
  local stop_on_first = stdnse.get_script_args({"brute-http-form.stop_on_first", "stop_on_first"})
  if stop_on_first == nil or stop_on_first == "" then stop_on_first = true
  else stop_on_first = (lower(stop_on_first) == "true" or stop_on_first == "1") end
  local login_path = stdnse.get_script_args({"brute-http-form.path", "path"}) or "/login"
  local user_field = stdnse.get_script_args({"brute-http-form.user_field", "user_field"}) or "username"
  local pass_field = stdnse.get_script_args({"brute-http-form.pass_field", "pass_field"}) or "password"
  local success_string = stdnse.get_script_args({"brute-http-form.success_string", "success_string"}) or ""
  local fail_string = stdnse.get_script_args({"brute-http-form.fail_string", "fail_string"}) or "login failed"

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
      local socket = new_socket()
      socket:set_timeout(timeout * 1000)
      local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then errors = errors + 1; return false end
        local body = user_field .. "=" .. nmap.url_encode(u) .. "&" .. pass_field .. "=" .. nmap.url_encode(p)
        local req = "POST " .. login_path .. " HTTP/1.0\r\nHost: " .. host.ip .. "\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " .. #body .. "\r\nConnection: close\r\n\r\n" .. body
        socket:send(req)
        local resp = socket:receive_bytes(2048)
        socket:close()
        if resp then
          local status_code = match(resp, "HTTP/%d%.%d (%d+)")
          local sc = status_code and tonumber(status_code) or 0
          local resp_lower = lower(resp)
          if success_string ~= "" and find(resp_lower, success_string:lower()) then
            return true
          end
          if fail_string ~= "" and find(resp_lower, fail_string:lower()) then
            return false
          end
          if sc == 302 then
            return true
          end
          if sc == 200 and not find(resp_lower, "login", 1, true) then
            return true
          end
          if sc == 401 or sc == 403 then
            return false
          end
        end
        return false
      end)
      if not ok then
        pcall(socket.close, socket)
      end
      if result then
        success_count = success_count + 1
        insert(found, {user = u, password = p, path = login_path})
        if stop_on_first then stop = true end
      end
      attempts = attempts + 1
      if delay > 0 and not stop then sleep(delay / 1000) end
    end
  end

  local elapsed = os.time() - start_time
  local out = output_table()
  out.service = "HTTP Form Auth"
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
