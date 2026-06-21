local stdnse = require "stdnse"
local nmap = require "nmap"
local os = require "os"
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

description = [[Attempts to brute-force Telnet credentials using user-provided credential lists.]]
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
      line = line:gsub("^%s+", ""):gsub("%s+$", "")
      if line ~= "" and line:byte() ~= 35 then
        insert(lines, line)
      end
    end
    f:close()
    return lines
  end
  local items = {}
  for item in val:gmatch("[^,]+") do
    item = item:gsub("^%s+", ""):gsub("%s+$", "")
    if item ~= "" then insert(items, item) end
  end
  return items
end

local IAC = char(255)
local WILL = char(251)
local WONT = char(252)
local DO = char(253)
local DONT = char(254)
local SB = char(250)
local SE = char(240)

local function telnet_negotiate(socket)
  local data = ""
  local buf = ""
  while true do
    local status, chunk = socket:receive_bytes(1)
    if not status then return data end
    buf = buf .. chunk
    while #buf >= 2 and buf:byte(1) == 255 do
      local cmd = buf:byte(2)
      if cmd == 255 then
        data = data .. char(255)
        buf = buf:sub(3)
      elseif cmd == 251 or cmd == 253 then
        local opt = #buf >= 3 and buf:byte(3) or 0
        if #buf >= 3 then
          if cmd == 251 then
            socket:send(IAC .. WONT .. char(opt))
          else
            socket:send(IAC .. DONT .. char(opt))
          end
          buf = buf:sub(4)
        else
          break
        end
      elseif cmd == 252 or cmd == 254 then
        buf = #buf >= 3 and buf:sub(4) or ""
      elseif cmd == 250 then
        local se_idx = buf:find(IAC .. SE, 1, true)
        if se_idx then
          buf = buf:sub(se_idx + 2)
        else
          break
        end
      elseif cmd == 240 then
        buf = buf:sub(3)
      else
        buf = buf:sub(3)
      end
    end
    if #buf > 0 and buf:byte(1) ~= 255 then
      data = data .. buf:sub(1, 1)
      buf = buf:sub(2)
    end
    if #data > 0 and (data:find("login") or data:find("Password") or data:find("#") or data:find("$") or data:find(">")) then
      break
    end
  end
  return data
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.number == 23 end

action = function(host, port)
  local users = load_list({"brute-telnet.users", "users"}, "root,admin")
  local passes = load_list({"brute-telnet.passwords", "passwords"}, "password,12345,admin")
  local delay = tonumber(stdnse.get_script_args({"brute-telnet.delay", "delay"}) or 100)
  local max_attempts = tonumber(stdnse.get_script_args({"brute-telnet.max_attempts", "max_attempts"}) or 1000)
  local timeout = tonumber(stdnse.get_script_args({"brute-telnet.timeout", "timeout"}) or 10)
  local stop_on_first = stdnse.get_script_args({"brute-telnet.stop_on_first", "stop_on_first"})
  if stop_on_first == nil or stop_on_first == "" then stop_on_first = true
  else stop_on_first = (stop_on_first:lower() == "true" or stop_on_first == "1") end

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
        local banner = telnet_negotiate(socket)
        if not banner:find("login") then
          socket:send("\r\n")
          local extra = telnet_negotiate(socket)
          banner = banner .. extra
        end
        if banner:find("login") then
          socket:send(u .. "\r\n")
          local pass_prompt = telnet_negotiate(socket)
          if pass_prompt:find("Password") then
            socket:send(p .. "\r\n")
            local shell_resp = telnet_negotiate(socket)
            socket:close()
            if shell_resp:find("#") or shell_resp:find("$") or shell_resp:find(">") or shell_resp:find("Last login") then
              return true
            end
            return false
          end
          socket:close()
          return false
        end
        socket:close()
        return false
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
  out.service = "Telnet"
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
