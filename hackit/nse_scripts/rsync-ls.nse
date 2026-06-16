local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
local bin = require "bin"

description = [[Lists rsync modules available on the target rsync server. Connects to rsync service, parses the banner for protocol version, and lists all available modules with comments and access restrictions.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and port.number == 873
end

local function parse_rsync_banner(banner)
  local info = {}
  banner = banner:gsub("%s+$", "")

  if banner:match("^@RSYNC") then
    info.rsync_detected = true
    info.protocol_version = banner:match("@RSYNC:(%d+)")
    if not info.protocol_version then
      info.protocol_version = banner:match("@RSYNC: (%d+)")
    end
    return info
  end

  info.banner = banner
  return info
end

local function parse_module_line(line)
  line = line:gsub("\r", "")
  if line == "" or line:match("^@") then return nil end

  local name, comment = line:match("^([%w][%w_%-%.]*)%s+(.+)$")
  if not name then
    name = line:match("^([%w][%w_%-%.]*)")
  end

  if name then
    name = name:gsub("%s+$", "")
    local entry = { name = name }
    if comment then
      entry.comment = comment:gsub("^%s+", ""):gsub("%s+$", "")
    end
    return entry
  end
  return nil
end

action = function(host, port)
  local result = stdnse.output_table()
  local socket = nmap.new_socket()
  socket:set_timeout(10000)

  local ok, err = pcall(socket.connect, socket, host.ip, port.number)
  if not ok then
    return stdnse.format_output(false, "Could not connect: " .. tostring(err))
  end

  local ok2, banner = pcall(socket.receive_lines, socket, 1)
  if not ok2 or not banner then
    socket:close()
    return stdnse.format_output(false, "No rsync banner received")
  end

  local banner_info = parse_rsync_banner(banner)

  if not banner_info.rsync_detected then
    socket:close()
    return stdnse.format_output(false, "Not an rsync service")
  end

  result.protocol_version = banner_info.protocol_version
  result.rsync_detected = true

  local ok3, serr = pcall(socket.send, socket, "#list\n")
  if not ok3 then
    socket:close()
    return stdnse.format_output(false, "Failed to send list request: " .. tostring(serr))
  end

  local ok4, response = pcall(socket.receive_buf, socket, "\n", 30)
  socket:close()

  if not ok4 or not response or response == "" then
    return stdnse.format_output(true, result)
  end

  local modules = {}
  for line in response:gmatch("([^\n]+)") do
    local module_entry = parse_module_line(line)
    if module_entry then
      table.insert(modules, module_entry)
    end
  end

  if #modules > 0 then
    result.modules = modules
    result.module_count = #modules
  end

  if not result.modules or result.module_count == 0 then
    result.modules_listable = false
    result.access_hint = "No modules listed (may require authentication)"
  end

  return stdnse.format_output(true, result)
end
