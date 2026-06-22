local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
local bin = require "bin"
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

description = [[Lists rsync modules available on the target rsync server. Connects to rsync service, parses the banner for protocol version, and lists all available modules with comments and access restrictions.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and port.number == 873
end

local function parse_rsync_banner(banner)
  local info = {}
  banner = gsub(banner, "%s+$", "")

  if match(banner, "^@RSYNC") then
    info.rsync_detected = true
    info.protocol_version = match(banner, "@RSYNC:(%d+)")
    if not info.protocol_version then
      info.protocol_version = match(banner, "@RSYNC: (%d+)")
    end
    return info
  end

  info.banner = banner
  return info
end

local function parse_module_line(line)
  line = gsub(line, "\r", "")
  if line == "" or match(line, "^@") then return nil end

  local name, comment = match(line, "^([%w][%w_%-%.]*)%s+(.+)$")
  if not name then
    name = match(line, "^([%w][%w_%-%.]*)")
  end

  if name then
    name = gsub(name, "%s+$", "")
    local entry = { name = name }
    if comment then
      entry.comment = gsub(comment, "^%s+", ""):gsub("%s+$", "")
    end
    return entry
  end
  return nil
end

action = function(host, port)
  local result = output_table()
  local socket = new_socket()
  socket:set_timeout(10000)

  local ok, err = pcall(socket.connect, socket, host.ip, port.number)
  if not ok then
    return format_output(false, "Could not connect: " .. tostring(err))
  end

  local ok2, banner = pcall(socket.receive_lines, socket, 1)
  if not ok2 or not banner then
    socket:close()
    return format_output(false, "No rsync banner received")
  end

  local banner_info = parse_rsync_banner(banner)

  if not banner_info.rsync_detected then
    socket:close()
    return format_output(false, "Not an rsync service")
  end

  result.protocol_version = banner_info.protocol_version
  result.rsync_detected = true

  local ok3, serr = pcall(socket.send, socket, "#list\n")
  if not ok3 then
    socket:close()
    return format_output(false, "Failed to send list request: " .. tostring(serr))
  end

  local ok4, response = pcall(socket.receive_buf, socket, "\n", 30)
  socket:close()

  if not ok4 or not response or response == "" then
    return format_output(true, result)
  end

  local modules = {}
  for line in gmatch(response, "([^\n]+)") do
    local module_entry = parse_module_line(line)
    if module_entry then
      insert(modules, module_entry)
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

  return format_output(true, result)
end
