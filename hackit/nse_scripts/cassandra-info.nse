local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"

description = [[Retrieves information from Apache Cassandra databases via the native transport protocol (port 9042). Attempts to identify the Cassandra version, cluster name, partitioner, schema version, and available keyspaces.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "database"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and port.number == 9042
end

local function recv_bytes(socket, timeout)
  socket:set_timeout(timeout)
  local ok, data = pcall(socket.receive_bytes, socket, 1)
  return ok, data
end

local function send_data(socket, data)
  local ok, err = pcall(socket.send, socket, data)
  return ok, err
end

local function parse_string(body, offset)
  if #body < offset + 1 then return nil, offset end
  local len = body:byte(offset) * 256 + body:byte(offset + 1)
  if #body < offset + 2 + len then return nil, offset end
  return body:sub(offset + 2, offset + 1 + len), offset + 2 + len
end

local function parse_string_list(body, offset)
  if #body < offset + 1 then return nil, offset end
  local count = body:byte(offset) * 256 + body:byte(offset + 1)
  offset = offset + 2
  local list = {}
  for _ = 1, count do
    local s, new_off = parse_string(body, offset)
    if not s then break end
    table.insert(list, s)
    offset = new_off
  end
  return list, offset
end

action = function(host, port)
  local result = stdnse.output_table()
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local ok, err = pcall(socket.connect, socket, host.ip, port.number)
  if not ok then
    return stdnse.format_output(false, "Failed to connect: " .. tostring(err))
  end

  local startup = string.char(0x04, 0x00, 0x00, 0x00, 0x00)
  local ok2, send_err = send_data(socket, startup)
  if not ok2 then
    socket:close()
    return stdnse.format_output(false, "Failed to send startup frame: " .. tostring(send_err))
  end

  local ok3, response = recv_bytes(socket, 5000)
  socket:close()

  if not ok3 or not response or #response < 9 then
    return stdnse.format_output(false, "No valid Cassandra response received")
  end

  local frame_version = response:byte(1)
  local frame_flags = response:byte(2)
  local stream_id = response:byte(3) + response:byte(4)
  local opcode = response:byte(5)
  local body_len = response:byte(6) * 256 * 256 * 256 + response:byte(7) * 256 * 256 +
                   response:byte(8) * 256 + response:byte(9)

  local opcodes = {
    [0x00] = "ERROR", [0x02] = "STARTUP", [0x04] = "READY",
    [0x06] = "AUTHENTICATE", [0x08] = "OPTIONS", [0x0A] = "RESULT",
  }
  result.opcode = opcodes[opcode] or string.format("0x%02x", opcode)

  result.protocol_version = frame_version & 0x7F
  result.direction = frame_version & 0x80 == 0 and "request" or "response"

  local body = response:sub(10)
  local offset = 1

  if opcode == 0x02 then
    local options, _ = parse_string_list(body, offset)
    if options then
      result.server_options = options
    end
  elseif opcode == 0x06 then
    local authenticator, _ = parse_string(body, offset)
    if authenticator then
      result.authenticator = authenticator
    end
  elseif opcode == 0x0A and #body >= 4 then
    local kind = body:byte(1) * 256 * 256 * 256 + body:byte(2) * 256 * 256 +
                 body:byte(3) * 256 + body:byte(4)
    local kinds = { [2] = "void", [3] = "rows" }
    result.result_kind = kinds[kind] or string.format("kind_%d", kind)
    offset = 5

    if kind == 3 and #body >= offset + 4 then
      local col_count = body:byte(offset) * 256 * 256 * 256 + body:byte(offset + 1) * 256 * 256 +
                        body:byte(offset + 2) * 256 + body:byte(offset + 3)
      result.column_count = col_count
      offset = offset + 4

      local pkey = body:byte(offset) * 256 + body:byte(offset + 1)
      offset = offset + 2
      local cluster_name, new_off = parse_string(body, offset + 2)
      if cluster_name then
        result.cluster_name = cluster_name
        offset = new_off
        local schema_version
        schema_version, offset = parse_string(body, offset)
        if schema_version then
          result.schema_version = schema_version
        end
        local partitioner
        partitioner, offset = parse_string(body, offset)
        if partitioner then
          result.partitioner = partitioner
        end
      end
    end
  end

  return stdnse.format_output(true, result)
end
