local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
local bit = require "bit"

description = [[Retrieves version information from MariaDB databases. Connects to the MySQL/MariaDB protocol port and reads the server version from the initial handshake. Inspects capabilities, auth plugin, and server status.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "database"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and port.number == 3306
end

local function parse_mysql_greeting(greeting, result)
  if #greeting < 5 then return end

  local protocol_version = string.byte(greeting, 5)
  result.protocol_version = protocol_version

  if #greeting > 5 then
    local null_pos = greeting:find("\x00", 6)
    if null_pos then
      local version = greeting:sub(6, null_pos - 1)
      result.server_version = version

      if version:lower():find("mariadb") then
        result.db_type = "MariaDB"
        local ver_num = version:match("%d+%.%d+%.%d+")
        if ver_num then
          result.version_number = ver_num
        end
      elseif version:lower():find("mysql") then
        result.db_type = "MySQL"
      elseif version:lower():find("percona") then
        result.db_type = "Percona Server"
      else
        result.db_type = "MySQL-compatible"
      end
    end
  end

  if #greeting >= 14 then
    local conn_id = string.byte(greeting, 10) +
                    string.byte(greeting, 11) * 256 +
                    string.byte(greeting, 12) * 65536 +
                    string.byte(greeting, 13) * 16777216
    result.connection_id = conn_id
  end

  if #greeting >= 9 then
    local auth_plugin_data = greeting:sub(9, 9 + 7)
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
    local cap_low = string.byte(greeting, 10) + string.byte(greeting, 11) * 256
    local cap_high = string.byte(greeting, 12) + string.byte(greeting, 13) * 256
    local cap = cap_low + cap_high * 65536

    local caps = {}
    for i, name in ipairs(capability_names) do
      if bit.band(cap, bit.lshift(1, i - 1)) ~= 0 then
        table.insert(caps, name)
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
    local auth_start = greeting:find("\x00", 36)
    if auth_start then
      local len_check = greeting:find("\x00", auth_start + 1)
      if len_check then
        auth_plugin_name = greeting:sub(auth_start + 1, len_check - 1)
        if auth_plugin_name and #auth_plugin_name > 0 then
          result.auth_plugin = auth_plugin_name
        end
      end
    end
  end

  if #greeting > 50 then
    local status_flags = string.byte(greeting, 15) + string.byte(greeting, 16) * 256
    result.server_status_flags = string.format("0x%04x", status_flags)
    result.autocommit = bit.band(status_flags, 0x0002) == 0
  end
end

action = function(host, port)
  local result = stdnse.output_table()
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local ok, err = pcall(socket.connect, socket, host.ip, port.number)
  if not ok then
    return stdnse.format_output(false, "Failed to connect: " .. tostring(err))
  end

  local ok2, greeting = pcall(socket.receive_buf, socket, 1024, true)
  socket:close()

  if not ok2 or not greeting or #greeting < 4 then
    return stdnse.format_output(false, "No valid MySQL/MariaDB greeting received")
  end

  parse_mysql_greeting(greeting, result)

  return stdnse.format_output(true, result)
end
