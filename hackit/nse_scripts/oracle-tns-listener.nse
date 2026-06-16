local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
local bit = require "bit"

description = [[Checks for Oracle TNS (Transparent Network Substrate) listener service. Attempts to extract listener version, service information, instance details, and security settings via the TNS protocol with multiple probes.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "database"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and port.number == 1521
end

local function build_tns_packet(connect_data)
  local header = string.char(
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x2e,
    0x00, 0x00, 0x08, 0x00, 0x7f, 0xff, 0x7f, 0x08,
    0x00, 0x00, 0x00, 0x01
  )

  local payload = string.char(0x00, 0x00, 0x00, 0x3c) ..
    string.rep("\x00", 32) ..
    "(" .. connect_data .. ")"

  local total_len = #header + #payload
  header = header:sub(1, 24) .. string.char(0x00, 0x00) ..
           string.char(bit.rshift(total_len, 8), bit.band(total_len, 0xFF)) ..
           header:sub(29)

  return header .. payload
end

local tns_probes = {
  { name = "VERSION", data = "CONNECT_DATA=(COMMAND=version)" },
  { name = "SERVICES", data = "CONNECT_DATA=(COMMAND=services)" },
  { name = "STATUS", data = "CONNECT_DATA=(COMMAND=status)" },
  { name = "PING", data = "CONNECT_DATA=(COMMAND=ping)" },
  { name = "DESCRIPTION", data = "DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=))(ADDRESS=(PROTOCOL=tcp))" },
}

action = function(host, port)
  local result = stdnse.output_table()
  local all_data = ""

  for _, probe in ipairs(tns_probes) do
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local ok, err = pcall(socket.connect, socket, host.ip, port.number)
    if not ok then
      socket:close()
      if _ == 1 then
        return stdnse.format_output(false, "Failed to connect: " .. tostring(err))
      end
      break
    end

    local pkt = build_tns_packet(probe.data)
    local ok2, send_err = pcall(socket.send, socket, pkt)
    if not ok2 then
      socket:close()
      break
    end

    local ok3, response = pcall(socket.receive_buf, socket, 2048, true)
    socket:close()

    if ok3 and response and #response > 4 then
      all_data = all_data .. response

      if response:match("Oracle") or response:match("TNS") then
        result.listener_detected = true
      end

      local version_match = response:match("TNSLSNR.-%d+%.%d+%.%d+%.%d+")
        or response:match("Version.-%d+%.%d+%.%d+%.%d+")
        or response:match("(%d+%.%d+%.%d+%.%d+%.%d+)")
      if version_match and not result.version then
        result.version = version_match
      end

      local product = response:match("PRODUCT%s*=%s*([%w%s]+)") or response:match("PRODUCT:([%w%s]+)")
      if product and not result.product then
        result.product = product:gsub("%s+$", "")
      end

      local services = {}
      for svc in response:gmatch("%(([A-Z][A-Z_]+)%s*=") do
        if not result[svc:lower()] then
          table.insert(services, svc)
        end
      end
      if #services > 4 then
        result.service_parameters = services
      end

      local instance = response:match("INSTANCE_NAME%s*=%s*([%w_]+)")
        or response:match("INST_NAME%s*=%s*([%w_]+)")
      if instance and not result.instance_name then
        result.instance_name = instance
      end

      local host_name = response:match("HOST_NAME%s*=%s*([%w_%.%-]+)")
      if host_name and not result.host_name then
        result.host_name = host_name
      end

      local sec = response:match("SECURITY[^)]*") or response:match("SEC_PROTOCOL[^)]*")
      if sec and not result.security then
        result.security = sec
      end
    end
  end

  if not result.listener_detected then
    return stdnse.format_output(false, "No TNS response received")
  end

  result.response_size = #all_data
  return stdnse.format_output(true, result)
end
