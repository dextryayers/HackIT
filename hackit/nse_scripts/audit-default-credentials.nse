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

description = [[Checks for default credentials across multiple services using user-provided credential entries.]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "audit"}

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

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
  local creds_arg = stdnse.get_script_args({"audit-default-credentials.credentials", "credentials"})
  local out = output_table()
  out.service = "Default Credentials Check"
  out.target = host.ip
  out.port = port.number

  if not creds_arg or creds_arg == "" then
    out.status = "NO_CREDENTIALS_SPECIFIED"
    out.message = "No credentials specified. Use audit-default-credentials.credentials arg (format: port:user:pass:service:vendor,port:user:pass:...)"
    out.risk = "LOW"
    return out
  end

  local matches = {}
  local entries = load_list({"audit-default-credentials.credentials", "credentials"})
  for _, entry in ipairs(entries) do
    local parts = {}
    for p in entry:gmatch("[^:]+") do
      insert(parts, p)
    end
    if #parts >= 3 then
      local eport = tonumber(parts[1])
      if eport == port.number then
        insert(matches, {)
          service = parts[4] or "Unknown",
          vendor = parts[5] or "Generic",
          username = parts[2],
          password = parts[3],
        }
      end
    end
  end

  if #matches > 0 then
    out.status = "DEFAULT_CREDENTIALS_FOUND"
    out.default_credential_patterns = matches
    out.match_count = #matches
    out.risk = "HIGH"
  else
    out.status = "NO_MATCHES"
    out.risk = "LOW"
    out.message = "No matching credential patterns for this port"
  end
  return out
end
