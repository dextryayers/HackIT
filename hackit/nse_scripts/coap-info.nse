local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
local bit = require "bit"

description = [[Detects CoAP (Constrained Application Protocol) services by sending discovery requests to /.well-known/core and common resource paths. Parses response codes, message types, resource links, and option fields.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "iot"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and port.number == 5683
end

local coap_resource_paths = {
  "/.well-known/core",
  "/sensor", "/actuator", "/status", "/temperature",
  "/humidity", "/light", "/pressure", "/config",
  "/info", "/health", "/data", "/telemetry",
  "/device", "/location", "/battery", "/time",
}

local function build_coap_get(path, message_id, token)
  local path_bytes = {}
  for segment in path:gmatch("[^/]+") do
    table.insert(path_bytes, segment)
  end

  local options = ""
  for _, seg in ipairs(path_bytes) do
    local seg_len = #seg
    if seg_len < 13 then
      options = options .. string.char(11 << 4 | seg_len) .. seg
    elseif seg_len < 270 then
      options = options .. string.char(11 << 4 | 13) .. string.char(seg_len - 13) .. seg
    end
  end

  local tkl = 1
  local code = 0x01
  local ver = 1
  local type = 0
  local first_byte = ver << 6 | type << 4 | tkl
  local mid_hi = bit.rshift(message_id, 8)
  local mid_lo = bit.band(message_id, 0xFF)

  local packet = string.char(first_byte, code, mid_hi, mid_lo, token)
  if #options > 0 then
    packet = packet .. options
  end
  packet = packet .. string.char(0xFF)

  return packet
end

local function parse_coap_response(response)
  local info = {}

  if #response < 4 then return nil end

  local first = string.byte(response, 1)
  info.version = bit.rshift(first, 6)
  info.type = bit.rshift(bit.band(first, 0x30), 4)
  info.tkl = bit.band(first, 0x0F)
  info.code = string.byte(response, 2)
  info.message_id = string.byte(response, 3) * 256 + string.byte(response, 4)

  local types = { "Confirmable", "Non-Confirmable", "Acknowledgement", "Reset" }
  info.type_name = types[info.type + 1] or "Unknown"

  local code_class = bit.rshift(info.code, 5)
  local code_detail = bit.band(info.code, 0x1F)

  local code_names = {
    [0.00] = "Empty",
    [0.01] = "GET", [0.02] = "POST", [0.03] = "PUT", [0.04] = "DELETE",
    [2.00] = "Created", [2.01] = "Deleted", [2.02] = "Valid",
    [2.03] = "Changed", [2.04] = "Content", [2.05] = "Continue",
    [4.00] = "Bad Request", [4.01] = "Unauthorized", [4.02] = "Bad Option",
    [4.03] = "Forbidden", [4.04] = "Not Found", [4.05] = "Method Not Allowed",
    [4.06] = "Not Acceptable", [5.00] = "Internal Server Error",
    [5.01] = "Not Implemented", [5.02] = "Bad Gateway",
    [5.03] = "Service Unavailable", [5.04] = "Gateway Timeout",
    [5.05] = "Proxying Not Supported",
  }
  info.code_name = code_names[code_class + code_detail / 100] or string.format("%d.%02d", code_class, code_detail)

  local payload_start = 4 + info.tkl
  if response:byte(payload_start) == 0xFF then
    payload_start = payload_start + 1
  end

  if payload_start <= #response then
    local payload = response:sub(payload_start)
    info.payload_size = #payload
    if payload:find("<") or payload:find("</") then
      info.resources = {}
      for res in payload:gmatch("<([^>]+)>") do
        table.insert(info.resources, res)
      end
      if #info.resources == 1 then
        local attrs = payload:match("<[^>]+>%s*(.*)")
        if attrs then
          info.resource_attributes = attrs
        end
      end
    end
  end

  return info
end

action = function(host, port)
  local result = stdnse.output_table()

  for _, path in ipairs(coap_resource_paths) do
    local socket = nmap.new_socket("udp")
    socket:set_timeout(3000)

    local ok, err = pcall(socket.connect, socket, host.ip, port.number)
    if not ok then
      socket:close()
      if _ == 1 then
        return stdnse.format_output(false, "Failed to connect: " .. tostring(err))
      end
      break
    end

    local mid = math.random(1, 65535)
    local token = math.random(1, 255)
    local packet = build_coap_get(path, mid, token)

    local ok2 = pcall(socket.send, socket, packet)
    if not ok2 then
      socket:close()
      break
    end

    local ok3, response = pcall(socket.receive_from, 10)
    socket:close()

    if ok3 and response and #response >= 4 then
      local info = parse_coap_response(response)
      if info then
        result.coap_detected = true
        result.coap_version = info.version
        result.message_type = info.type_name
        result.message_id = info.message_id
        result.response_code = info.code_name

        if info.resources then
          result.resources = info.resources
          result.resource_count = #info.resources
        end

        if info.payload_size then
          result.payload_size = info.payload_size
        end

        if path == "/.well-known/core" and info.resources then
          result.core_link_format = info.resources
        end

        return stdnse.format_output(true, result)
      end
    end
  end

  return stdnse.format_output(false, "No CoAP response received")
end
