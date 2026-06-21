local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
local bit = require "bit"
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

description = [[Checks for Oracle TNS (Transparent Network Substrate) listener service. Attempts to extract listener version, service information, instance details, and security settings via the TNS protocol with multiple probes.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "database"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and port.number == 1521
end

local function build_tns_packet(connect_data)
  local header = char(
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x2e,
    0x00, 0x00, 0x08, 0x00, 0x7f, 0xff, 0x7f, 0x08,
    0x00, 0x00, 0x00, 0x01
  )

  local payload = char(0x00, 0x00, 0x00, 0x3c) ..
    rep("\x00", 32) ..
    "(" .. connect_data .. ")"

  local total_len = #header + #payload
  header = header:sub(1, 24) .. char(0x00, 0x00) ..
           char(bit.rshift(total_len, 8), bit.band(total_len, 0xFF)) ..
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
  local result = output_table()
  local all_data = ""

  for _, probe in ipairs(tns_probes) do
    local socket = new_socket()
    socket:set_timeout(5000)

    local ok, err = pcall(socket.connect, socket, host.ip, port.number)
    if not ok then
      socket:close()
      if _ == 1 then
        return format_output(false, "Failed to connect: " .. tostring(err))
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
          insert(services, svc)
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
    return format_output(false, "No TNS response received")
  end

  result.response_size = #all_data
  return format_output(true, result)
end
