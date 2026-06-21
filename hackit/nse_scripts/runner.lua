local io = require "io"
local os = require "os"
local lfs = require "lfs"
local coroutine = require "coroutine"
local debug = require "debug"
local package = require "package"

local runner = {}
local timeout_protect = require "timeout_protect"
local category_map = require "category_map"



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

local SCRIPTS_DIR = os.getenv("NSE_SCRIPTS_DIR") or "."

local socket_available, socket = pcall(require, "socket")
local nmap_available = false

local env_cache = {}

local function make_socket(target, port, banner)
  local sock = {
    _connected = false,
    _sock = nil,
    _buf = "",
  }

  function sock:set_timeout(ms)
    if self._sock then
      self._sock:settimeout(ms / 1000)
    end
  end

  function sock:connect(host, p)
    if socket_available then
      local s, err = socket.tcp()
      if not s then return false, err end
      s:settimeout(10)
      local ok, cerr = s:connect(host or target, p or port)
      if not ok then return false, cerr end
      self._sock = s
      self._connected = true
      return true
    end
    if nmap_available then
      local s = nmap.new_socket()
      if s then
        local ok, err = s:connect(host or target, p or port)
        if not ok then return false, err end
        self._sock = s
        self._connected = true
        return true
      end
    end
    return false, "no socket backend available"
  end

  function sock:send(data)
    if not self._sock then return false, "not connected" end
    if socket_available then
      return self._sock:send(data)
    end
    if nmap_available then
      return self._sock:send(data)
    end
    return false, "no socket backend"
  end

  function sock:receive_buf(pattern, timeout)
    if not self._sock then return false, "not connected" end
    if socket_available then
      self._sock:settimeout((timeout or 5000) / 1000)
      if pattern == "\r\n" or pattern == "\n" then
        local line, err = self._sock:receive("*l")
        if line then
          self._buf = self._buf .. line .. "\n"
          return true, line
        end
        return false, err
      end
      local data, err = self._sock:receive("*a")
      if data then
        self._buf = self._buf .. data
        return true, data
      end
      return false, err
    end
    if nmap_available then
      return self._sock:receive_buf(pattern, timeout)
    end
    return false, "no socket backend"
  end

  function sock:receive_lines(timeout)
    if not self._sock then return false, "not connected" end
    if socket_available then
      self._sock:settimeout((timeout or 5000) / 1000)
      local data, err = self._sock:receive("*a")
      if data then return true, data end
      return false, err
    end
    if nmap_available then
      return self._sock:receive_buf("\n", timeout)
    end
    return false, "no socket backend"
  end

  function sock:close()
    if self._sock then
      if socket_available then
        self._sock:close()
      elseif nmap_available then
        pcall(function() self._sock:close() end)
      end
      self._sock = nil
    end
    self._connected = false
  end

  return sock
end

local function make_env(target, port, banner, script_name)
  local host = {
    ip = target,
    targetname = target,
    name = target,
    os = "unknown",
  }

  local port_info = {
    number = port,
    protocol = "tcp",
    state = "open",
    service = "unknown",
  }

  local env = {
    host = host,
    port = port_info,
    nmap = {
      new_socket = function()
        return make_socket(target, port, banner)
      end,
    },
    stdnse = {
      format_output = function(status, msg)
        if type(msg) == "table" then
          return msg
        end
        return { status = status, message = msg }
      end,
      output_table = function()
        return {}
      end,
      get_script_args = function()
        return {}
      end,
      debug = function(level, msg)
        io.stderr:write("[DEBUG] " .. tostring(msg) .. "\n")
      end,
      verbose = function(level, msg)
        io.stderr:write("[VERBOSE] " .. tostring(msg) .. "\n")
      end,
      error = function(msg)
        return { error = msg }
      end,
    },
    shortport = {
      port_or_service = function(port_num, service)
        return function(h, p)
          return p.number == port_num or p.service == service
        end
      end,
      portnumber = function(port_num)
        return function(h, p)
          return p.number == port_num
        end
      end,
    },
    http = {
      get = function(h, p, path)
        if socket_available then
          local s, err = socket.tcp()
          if not s then return nil end
          s:settimeout(10)
          local ok = s:connect(h.ip or h, p.number or p)
          if not ok then return nil end
          local req = "GET " .. (path or "/") .. " HTTP/1.0\r\nHost: " .. (h.ip or h) .. "\r\nConnection: close\r\n\r\n"
          s:send(req)
          local resp, rerr = s:receive("*a")
          s:close()
          if not resp then return nil end
          local headers = {}
          local body = ""
          local header_end = resp:find("\r\n\r\n")
          if header_end then
            local header_section = resp:sub(1, header_end - 1)
            for line in header_section:gmatch("[^\r\n]+") do
              local key, val = line:match("^([^:]+):%s*(.+)$")
              if key then
                headers[key:lower()] = val
              end
            end
            body = resp:sub(header_end + 4)
          end
          return { header = headers, body = body, status = 200 }
        end
        return nil
      end,
      head = function(h, p, path)
        return http.get(h, p, path)
      end,
    },
    dns = {
      query = function(domain, opts)
        return {}
      end,
    },
    tls = {
      client_hello = function(protocol, opts)
        return ""
      end,
      server_hello_done = function()
        return true
      end,
    },
    ip = {
      toip = function(hostname)
        return hostname
      end,
    },
    math = math,
    string = string,
    table = table,
    os = os,
    io = io,
    pcall = pcall,
    xpcall = xpcall,
    error = error,
    type = type,
    pairs = pairs,
    ipairs = ipairs,
    tostring = tostring,
    tonumber = tonumber,
    unpack = table.unpack or unpack,
    select = select,
    assert = assert,
    next = next,
    rawget = rawget,
    rawset = rawset,
    setmetatable = setmetatable,
    getmetatable = getmetatable,
    coroutine = coroutine,
    string = string,
    table = table,
    math = math,
    _VERSION = _VERSION,
  }

  env._G = env
  env.require = function(name)
    if env[name] then
      return env[name]
    end
    if package.loaded[name] then
      return package.loaded[name]
    end
    local ok, mod = pcall(require, name)
    if ok and mod then
      return mod
    end
    return {}
  end

  return env, host, port_info
end

local function load_script_env(script_name, target, port, banner)
  local filepath = SCRIPTS_DIR .. "/" .. script_name
  if not filepath:match("%.nse$") then
    filepath = filepath .. ".nse"
  end

  local f, err = io.open(filepath, "r")
  if not f then
    return nil, "cannot open script: " .. (err or "file not found")
  end
  local code = f:read("*a")
  f:close()

  if not code then
    return nil, "empty script file"
  end

  local env, host, port_info = make_env(target, port, banner, script_name)

  local chunk, cerr = load(code, filepath, "t", env)
  if not chunk then
    return nil, "load error: " .. (cerr or "unknown")
  end

  local ok, lerr = pcall(chunk)
  if not ok then
    return nil, "chunk error: " .. (lerr or "unknown")
  end

  local action = env.action
  if not action then
    return nil, "script has no action() function"
  end

  local portrule = env.portrule
  if portrule then
    local ok2, match = pcall(portrule, host, port_info)
    if ok2 and not match then
      return nil, "portrule did not match"
    end
  end

  return function()
    return action(host, port_info)
  end, env
end

function runner.run_single(script_name, target, port, banner)
  local action_fn, err = load_script_env(script_name, target, port, banner)
  if not action_fn then
    return { status = false, error = err, script = script_name }
  end

  local ok, result = pcall(action_fn)
  if not ok then
    return { status = false, error = tostring(result), script = script_name }
  end

  return {
    status = true,
    result = result,
    script = script_name,
    target = target,
    port = port,
  }
end

function runner.run_single_timeout(script_name, target, port, banner, timeout)
  local action_fn, err = load_script_env(script_name, target, port, banner)
  if not action_fn then
    return { status = false, error = err, script = script_name }
  end

  local ok, result = timeout_protect.with_timeout(timeout or 10, action_fn)
  if not ok then
    return { status = false, error = tostring(result), script = script_name }
  end

  return {
    status = true,
    result = result,
    script = script_name,
    target = target,
    port = port,
  }
end

local function co_schedule(cos)
  local active = {}
  for i, co in ipairs(cos) do
    active[i] = { co = co, status = "ready" }
  end

  local finished = 0
  local total = #active
  local results = {}

  while finished < total do
    for i, entry in ipairs(active) do
      if entry.status == "ready" then
        local ok, res = coroutine.resume(entry.co)
        if not ok then
          entry.status = "done"
          results[i] = { status = false, error = tostring(res) }
          finished = finished + 1
        elseif coroutine.status(entry.co) == "dead" then
          entry.status = "done"
          results[i] = res or { status = true, result = nil }
          finished = finished + 1
        end
      end
    end
    if finished < total then
      coroutine.yield()
    end
  end

  return results
end

function runner.run_parallel(scripts, target, port, banner, callback)
  if type(scripts) == "string" then
    scripts = { scripts }
  end

  local cos = {}
  local script_names = {}

  for i, script_name in ipairs(scripts) do
    script_names[i] = script_name
    cos[i] = coroutine.create(function()
      local result = runner.run_single_timeout(script_name, target, port, banner, 10)
      if callback then
        callback(result)
      end
      return result
    end)
  end

  local scheduler = coroutine.create(function()
    return co_schedule(cos)
  end)

  local ok, results = coroutine.resume(scheduler)
  if not ok then
    return { status = false, error = tostring(results) }
  end

  while coroutine.status(scheduler) ~= "dead" do
    ok, results = coroutine.resume(scheduler)
    if not ok then
      return { status = false, error = tostring(results) }
    end
  end

  local final = {}
  for i, script_name in ipairs(script_names) do
    final[i] = results[i] or { status = false, error = "no result", script = script_name }
    final[i].script = script_name
    final[i].target = target
    final[i].port = port
  end

  return final
end

function runner.discover_scripts()
  local dir = SCRIPTS_DIR
  local categorized = {}

  local f, err = io.popen("ls " .. dir .. "/*.nse 2>/dev/null")
  if not f then
    local handle = io.popen("find " .. dir .. " -maxdepth 1 -name '*.nse' 2>/dev/null")
    if not handle then
      return {}
    end
    f = handle
  end

  for file in f:lines() do
    local basename = file:match("/([^/]+)%.nse$")
    if not basename then
      basename = file:match("([^/\\]+)%.nse$")
    end
    if basename then
      local cat = category_map.get(basename)
      categorized[cat] = categorized[cat] or {}
      insert(categorized[cat], basename)
    end
  end
  f:close()

  return categorized
end

function runner.get_script_info(script_name)
  local filepath = SCRIPTS_DIR .. "/" .. script_name
  if not filepath:match("%.nse$") then
    filepath = filepath .. ".nse"
  end

  local f, err = io.open(filepath, "r")
  if not f then
    return nil, "cannot open: " .. (err or "not found")
  end

  local info = {
    name = script_name:gsub("%.nse$", ""),
    description = "",
    author = "",
    license = "",
    categories = {},
  }

  for line in f:lines() do
    if line:match("^description%s*=%s*%[%[") then
      local desc = line:match("^description%s*=%s*%[%[(.-)%]%]")
      if desc then
        info.description = desc
      else
        local parts = {line:match("%[%[(.*)$")}
        if parts[1] then
          local desc_lines = {parts[1]}
          for next_line in f:lines() do
            if next_line:match("%]%]") then
              local end_part = next_line:match("^(.-)%]%]")
              if end_part and end_part ~= "" then
                insert(desc_lines, end_part)
              end
              break
            end
            insert(desc_lines, next_line)
          end
          info.description = concat(desc_lines, " ")
        end
      end
    elseif line:match("^author%s*=") then
      info.author = line:match('"([^"]+)"') or ""
    elseif line:match("^license%s*=") then
      info.license = line:match('"([^"]+)"') or ""
    elseif line:match("^categories%s*=") then
      local cat_str = line:match("{(.-)}")
      if cat_str then
        for cat in cat_str:gmatch('"([^"]+)"') do
          insert(info.categories, cat)
        end
      end
    end
  end

  f:close()
  return info
end

function runner.list_scripts()
  local categories = runner.discover_scripts()
  local all = {}
  for cat, scripts in pairs(categories) do
    for _, name in ipairs(scripts) do
      all[name] = cat
    end
  end
  return all
end

function runner.scripts_by_category(category)
  local all = runner.discover_scripts()
  return all[category] or {}
end

setmetatable(runner, {
  __call = function(_, ...)
    return runner.run_parallel(...)
  end,
})

return runner
