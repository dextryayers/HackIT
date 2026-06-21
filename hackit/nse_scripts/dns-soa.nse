local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"



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

description = [[
Retrieves and analyzes the Start of Authority (SOA) record from the target DNS server
for the specified domain. The SOA record contains essential zone configuration
parameters: primary nameserver (MNAME), responsible party email (RNAME), serial
number (for zone change tracking), refresh interval (how often secondaries poll),
retry interval (after failed refresh), expire time (when secondaries stop serving),
and minimum TTL (NXDOMAIN caching duration). Analyzes these values against best
practice recommendations and detects potential misconfigurations such as serial
number format issues, excessively long/short intervals, and stale zone data. The
serial number is parsed as a date-based or increment-only format.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(53, "domain")

action = function(host, port)
  local result = output_table()
  local domain = host.targetname

  if not domain or #domain == 0 then
    result.status = "error"
    result.reason = "No target domain name specified"
    return result
  end

  local opts = { host = host.ip, port = port.number, dtype = "SOA", timeout = 5000, retries = 2 }

  local ok, soa_result = pcall(dns.query, domain, opts)

  if not ok or not soa_result or #soa_result == 0 then
    local opts2 = { host = host.ip, port = port.number, dtype = "SOA", timeout = 10000, retries = 2 }
    local ok2, soa_result2 = pcall(dns.query, domain, opts2)
    if ok2 then
      soa_result = soa_result2
      ok = true
    end
  end

  result.status = "success"
  result.domain = domain
  result.server = host.ip .. ":" .. port.number

  if not ok or not soa_result or #soa_result == 0 then
    result.soa_found = false
    result.reason = "No SOA record found"
    return result
  end

  local soa = soa_result
  if type(soa) == "table" and soa[1] and type(soa[1]) == "table" then
    soa = soa[1]
  end

  local mname = soa.mname or (type(soa) == "table" and soa[1]) or "N/A"
  local rname = soa.rname or (type(soa) == "table" and soa[2]) or "N/A"
  local serial = soa.serial or (type(soa) == "table" and soa[3]) or 0
  local refresh = soa.refresh or (type(soa) == "table" and soa[4]) or 0
  local retry = soa.retry or (type(soa) == "table" and soa[5]) or 0
  local expire = soa.expire or (type(soa) == "table" and soa[6]) or 0
  local minimum = soa.minimum or (type(soa) == "table" and soa[7]) or 0

  if type(rname) == "string" then
    rname = rname:gsub("%.", "@")
    local at_count = 0
    for c in rname:gmatch("@") do at_count = at_count + 1 end
    if at_count > 1 then
      local parts = strsplit("@", rname)
      rname = parts[1] .. "@" .. concat(parts, ".", 2)
    end
  end

  local serial_str = tostring(serial)
  local serial_format = "unknown"
  if #serial_str >= 10 and serial_str:match("^%d%d%d%d%d%d%d%d%d+$") then
    local date_part = serial_str:sub(1, 8)
    local rev_part = serial_str:sub(9)
    serial_format = "date-based (YYYYMMDD" .. (rev_part and ("+" .. rev_part) or "") .. ")"
  elseif serial_str:match("^%d+$") then
    serial_format = "increment-only"
  end

  local recommendations = {}
  local issues = {}

  if tonumber(refresh) and tonumber(refresh) < 3600 then
    insert(issues, "Refresh interval too short (" .. refresh .. "s)")
  elseif tonumber(refresh) and tonumber(refresh) > 86400 then
    insert(issues, "Refresh interval too long (" .. refresh .. "s)")
  end

  if tonumber(retry) and tonumber(refresh) and tonumber(retry) >= tonumber(refresh) then
    insert(issues, "Retry interval should be less than refresh interval")
  end

  if tonumber(expire) and tonumber(expire) < 604800 then
    insert(issues, "Expire time too short (" .. expire .. "s < 7 days)")
  end

  if tonumber(minimum) and tonumber(minimum) > 86400 then
    insert(issues, "Minimum TTL too long (" .. minimum .. "s)")
  end

  result.soa_found = true
  result.mname = tostring(mname):gsub("%.$", "")
  result.rname = tostring(rname)
  result.serial = tonumber(serial) or 0
  result.serial_format = serial_format
  result.refresh_seconds = tonumber(refresh) or 0
  result.retry_seconds = tonumber(retry) or 0
  result.expire_seconds = tonumber(expire) or 0
  result.minimum_ttl_seconds = tonumber(minimum) or 0

  result.refresh_hours = tonumber(refresh) and format("%.1f", tonumber(refresh) / 3600) or "0"
  result.retry_hours = tonumber(retry) and format("%.1f", tonumber(retry) / 3600) or "0"
  result.expire_days = tonumber(expire) and format("%.1f", tonumber(expire) / 86400) or "0"
  result.minimum_ttl_hours = tonumber(minimum) and format("%.1f", tonumber(minimum) / 3600) or "0"

  if #issues > 0 then
    result.issues = issues
    result.configuration_issues = true
  else
    result.configuration_issues = false
  end

  return result
end
