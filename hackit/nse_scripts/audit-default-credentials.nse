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

description = [[Checks for default credentials across multiple services using user-provided credential entries.]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "audit"}

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
    for p in gmatch(entry, "[^:]+") do
      insert(parts, p)
    end
    if #parts >= 3 then
      local eport = tonumber(parts[1])
      if eport == port.number then
        insert(matches, {
          service = parts[4] or "Unknown",
          vendor = parts[5] or "Generic",
          username = parts[2],
          password = parts[3],
        })
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
