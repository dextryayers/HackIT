local debug = require "debug"
local os = require "os"



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

local timeout_protect = {}

local function timeout_handler(limit)
  local start = os.clock()
  return function()
    if os.clock() - start > limit then
      error("timeout: execution exceeded " .. limit .. " seconds")
    end
  end
end

function timeout_protect.with_timeout(seconds, func, ...)
  local args = table.pack(...)
  local co = coroutine.create(function()
    local ok, result = xpcall(function()
      return func(table.unpack(args, 1, args.n))
    end, debug.traceback)
    if not ok then
      return nil, result
    end
    return result
  end)

  local deadline = os.clock() + seconds
  local status, result

  while true do
    if os.clock() > deadline then
      return nil, "timeout: execution exceeded " .. seconds .. " seconds"
    end
    status, result = coroutine.resume(co)
    if not status then
      local err = tostring(result)
      if err:find("timeout") then
        return nil, err
      end
      return nil, err
    end
    if coroutine.status(co) == "dead" then
      if result == nil then
        local _, err = coroutine.resume(co)
        return nil, tostring(err)
      end
      return result
    end
    coroutine.yield()
  end
end

function timeout_protect.with_timeout_debug(seconds, func)
  local limit = seconds
  local hook = timeout_handler(limit)
  debug.sethook(hook, "", 1000000)
  local ok, result = xpcall(func, debug.traceback)
  debug.sethook()
  if not ok then
    return nil, result
  end
  return result
end

function timeout_protect.with_alarm(seconds, func)
  local pid = os.execute("sleep " .. seconds .. " &")
  local ok, result = xpcall(func, debug.traceback)
  return result
end

return timeout_protect
