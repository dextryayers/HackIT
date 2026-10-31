local stdnse = require "stdnse"
local nmap = require "nmap"
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
local msleep = function(ms)
    if stdnse and stdnse.sleep then
        return stdnse.sleep((ms or 0) / 1000)
    end
    if nmap.msleep then
        return nmap.msleep(ms or 0)
    end
    local deadline = nmap.clock() + (ms or 0) / 1000
    while nmap.clock() < deadline do end
    return true
end
local new_socket = nmap.new_socket
local resolve = nmap.resolve

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    if stdnse and stdnse.sleep then
        return stdnse.sleep(seconds)
    end
    if nmap.msleep then
        return nmap.msleep(math.max(0, math.floor((seconds or 0) * 1000)))
    end
    local deadline = nmap.clock() + (seconds or 0)
    while nmap.clock() < deadline do end
    return true
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

description = [[Tests Redis authentication using user-provided passwords. No hardcoded credentials.]]
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

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 6379 or port.service == "redis") end

action = function(host, port)
  local passes = load_list({"redis-empty-password.passwords", "passwords", "brute-redis.passwords", "redis-empty-password.users", "users", "brute-redis.users"})
  local timeout = tonumber(stdnse.get_script_args({"redis-empty-password.timeout", "timeout"}) or 10)

  local function test_auth(pass)
    local sock = new_socket()
    sock:set_timeout(timeout * 1000)
    local ok, authed = pcall(function()
      local status = sock:connect(host.ip, port)
      if not status then return nil end
      sock:send("AUTH " .. pass .. "\r\n")
      local resp = sock:receive_bytes(10)
      sock:close()
      if resp and find(resp, "+OK") then return true end
      return false
    end)
    if not ok then pcall(function() sock:close() end) end
    return ok and authed
  end

  local function check_noauth()
    local sock = new_socket()
    sock:set_timeout(3000)
    local ok, res = pcall(function()
      local status = sock:connect(host.ip, port)
      if not status then return false end
      sock:send("INFO\r\n")
      local resp = sock:receive_buf("\r\n", 5000)
      sock:close()
      if resp and (match(resp, "# Server") or match(resp, "redis_version")) then
        return {vulnerability = true, severity = "CRITICAL", details = "Redis has no password configured"}
      end
      if resp and (match(resp, "NOAUTH") or match(resp, "Authentication required")) then
        return {vulnerability = false}
      end
      return false
    end)
    if not ok then pcall(function() sock:close() end) end
    return ok and res
  end

  local noauth = check_noauth()
  if noauth then
    if type(noauth) == "table" and noauth.vulnerability then
      local result = noauth
      local ver = nil
      local sock = new_socket()
      sock:set_timeout(3000)
      pcall(function()
        if sock:connect(host.ip, port) then
          sock:send("INFO\r\n")
          local resp = sock:receive_buf("\r\n", 5000)
          ver = resp and match(resp, "redis_version:([^\r\n]+)")
          sock:close()
        end
      end)
      if ver then result.version = ver end
      result.vulnerability = true
      result.severity = "CRITICAL"
      result.details = "Redis has no password configured - full unauthenticated access available"
      return result
    end
    return format_output(false, "Redis requires authentication")
  end

  if #passes == 0 then
    return format_output(false, "No passwords provided. Use redis-empty-password.passwords script arg")
  end

  for _, p in ipairs(passes) do
    local result = test_auth(p)
    if result then
      local out = output_table()
      out.vulnerability = true
      out.severity = "CRITICAL"
      out.details = "Redis weak credentials found: " .. p
      return out
    end
  end

  return format_output(false, "No Redis weak credentials found")
end
