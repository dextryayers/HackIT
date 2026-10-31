local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
-- Lua 5.4 has no "bit" module; this is a 32-bit compatible replacement.
local bit = (function()
    local floor = math.floor
    local function toint(x) return floor(x) & 0xFFFFFFFF end
    local function fold(fn, a, ...)
        local r = toint(a)
        for i = 1, select("#", ...) do
            r = toint(fn(r, select(i, ...)))
        end
        return r
    end
    return {
        band = function(...) return fold(function(x, y) return x & y end, ...) end,
        bor = function(...) return fold(function(x, y) return x | y end, ...) end,
        bxor = function(...) return fold(function(x, y) return x ~ y end, ...) end,
        bnot = function(x) return (~toint(x)) & 0xFFFFFFFF end,
        lshift = function(x, n) return (toint(x) << (n & 31)) & 0xFFFFFFFF end,
        rshift = function(x, n) return toint(x) >> (n & 31) end,
        arshift = function(x, n) return toint(x) >> (n & 31) end,
        tobit = function(x) return toint(x) end,
        tohex = function(x) return format("%08x", toint(x)) end,
    }
end)()
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

description = [[Retrieves version information from MariaDB databases. Connects to the MySQL/MariaDB protocol port and reads the server version from the initial handshake. Inspects capabilities, auth plugin, and server status.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "database"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and port.number == 3306
end

local function parse_mysql_greeting(greeting, result)
  if #greeting < 5 then return end

  local protocol_version = byte(greeting, 5)
  result.protocol_version = protocol_version

  if #greeting > 5 then
    local null_pos = find(greeting, "\x00", 6)
    if null_pos then
      local version = sub(greeting, 6, null_pos - 1)
      result.server_version = version

      if lower(version):find("mariadb") then
        result.db_type = "MariaDB"
        local ver_num = match(version, "%d+%.%d+%.%d+")
        if ver_num then
          result.version_number = ver_num
        end
      elseif lower(version):find("mysql") then
        result.db_type = "MySQL"
      elseif lower(version):find("percona") then
        result.db_type = "Percona Server"
      else
        result.db_type = "MySQL-compatible"
      end
    end
  end

  if #greeting >= 14 then
    local conn_id = byte(greeting, 10) +
                    byte(greeting, 11) * 256 +
                    byte(greeting, 12) * 65536 +
                    byte(greeting, 13) * 16777216
    result.connection_id = conn_id
  end

  if #greeting >= 9 then
    local auth_plugin_data = sub(greeting, 9, 9 + 7)
    result.auth_plugin_data_present = #auth_plugin_data > 0
  end

  local capability_names = {
    "CLIENT_LONG_PASSWORD", "CLIENT_FOUND_ROWS", "CLIENT_LONG_FLAG",
    "CLIENT_CONNECT_WITH_DB", "CLIENT_NO_SCHEMA", "CLIENT_COMPRESS",
    "CLIENT_ODBC", "CLIENT_LOCAL_FILES", "CLIENT_IGNORE_SPACE",
    "CLIENT_PROTOCOL_41", "CLIENT_INTERACTIVE", "CLIENT_SSL",
    "CLIENT_IGNORE_SIGPIPE", "CLIENT_TRANSACTIONS", "CLIENT_RESERVED",
    "CLIENT_SECURE_CONNECTION", "CLIENT_MULTI_STATEMENTS",
    "CLIENT_MULTI_RESULTS", "CLIENT_PS_MULTI_RESULTS", "CLIENT_PLUGIN_AUTH",
    "CLIENT_CONNECT_ATTRS", "CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA",
    "CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS", "CLIENT_SESSION_TRACK",
    "CLIENT_DEPRECATE_EOF",
  }

  if #greeting >= 13 then
    local cap_low = byte(greeting, 10) + byte(greeting, 11) * 256
    local cap_high = byte(greeting, 12) + byte(greeting, 13) * 256
    local cap = cap_low + cap_high * 65536

    local caps = {}
    for i, name in ipairs(capability_names) do
      if bit.band(cap, bit.lshift(1, i - 1)) ~= 0 then
        insert(caps, name)
      end
    end
    if #caps > 0 then
      result.server_capabilities = caps
      result.capability_count = #caps
    end

    result.compression_supported = bit.band(cap, 0x0020) ~= 0
    result.ssl_supported = bit.band(cap, 0x0800) ~= 0
    result.plugin_auth_supported = bit.band(cap, 0x080000) ~= 0
    result.multi_statements_supported = bit.band(cap, 0x010000) ~= 0
  end

  if #greeting > 35 then
    local auth_plugin_name
    local auth_start = find(greeting, "\x00", 36)
    if auth_start then
      local len_check = find(greeting, "\x00", auth_start + 1)
      if len_check then
        auth_plugin_name = sub(greeting, auth_start + 1, len_check - 1)
        if auth_plugin_name and #auth_plugin_name > 0 then
          result.auth_plugin = auth_plugin_name
        end
      end
    end
  end

  if #greeting > 50 then
    local status_flags = byte(greeting, 15) + byte(greeting, 16) * 256
    result.server_status_flags = format("0x%04x", status_flags)
    result.autocommit = bit.band(status_flags, 0x0002) == 0
  end
end

action = function(host, port)
  local result = output_table()
  local socket = new_socket()
  socket:set_timeout(5000)

  local ok, err = pcall(socket.connect, socket, host.ip, port.number)
  if not ok then
    return format_output(false, "Failed to connect: " .. tostring(err))
  end

  local ok2, greeting = pcall(socket.receive_buf, socket, 1024, true)
  socket:close()

  if not ok2 or not greeting or #greeting < 4 then
    return format_output(false, "No valid MySQL/MariaDB greeting received")
  end

  parse_mysql_greeting(greeting, result)

  return format_output(true, result)
end
