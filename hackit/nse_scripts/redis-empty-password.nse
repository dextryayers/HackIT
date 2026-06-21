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

description = [[Tests Redis authentication using user-provided passwords. No hardcoded credentials.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

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
      if resp and resp:find("+OK") then return true end
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
      if resp and (resp:match("# Server") or resp:match("redis_version")) then
        return {vulnerability = true, severity = "CRITICAL", details = "Redis has no password configured"}
      end
      if resp and (resp:match("NOAUTH") or resp:match("Authentication required")) then
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
          ver = resp and resp:match("redis_version:([^\r\n]+)")
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
