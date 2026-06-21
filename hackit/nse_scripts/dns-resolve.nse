local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"
local string = require "string"



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
Performs comprehensive forward DNS resolution on the target hostname. Queries for A
(IPv4), AAAA (IPv6), CNAME (canonical name), and MX (mail exchange) records to map
domain names to their associated IP addresses and services. Uses the target DNS server
for resolution with configurable timeout and retry logic. Results are categorized by
record type for easy analysis. Useful for domain infrastructure mapping and
troubleshooting DNS resolution issues.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(53, "domain")

local function safe_query(fqdn, opts)
  local ok, res = pcall(dns.query, fqdn, opts)
  if ok and res then
    local entries = {}
    for _, v in ipairs(res) do
      insert(entries, tostring(v))
    end
    return entries
  end
  return nil
end

action = function(host, port)
  local result = output_table()

  if not host.targetname then
    result.status = "error"
    result.reason = "No target hostname available for resolution"
    return result
  end

  local base_opts = {
    host = host.ip,
    port = port.number,
    timeout = 5000,
    retries = 2
  }

  local record_types = { "A", "AAAA", "CNAME", "MX", "TXT", "NS" }
  local resolved = {}

  for _, rtype in ipairs(record_types) do
    local opts = {}
    for k, v in pairs(base_opts) do opts[k] = v end
    opts.dtype = rtype
    local entries = safe_query(host.targetname, opts)
    if entries and #entries > 0 then
      resolved[rtype] = entries
    end
  end

  result.status = "success"
  result.domain = host.targetname
  result.server = host.ip

  local count = 0
  for _, records in pairs(resolved) do
    count = count + #records
  end

  result.total_records = count

  if resolved.A then
    result.a_records = resolved.A
  end
  if resolved.AAAA then
    result.aaaa_records = resolved.AAAA
  end
  if resolved.CNAME then
    result.cname = resolved.CNAME
  end
  if resolved.MX then
    result.mx_records = resolved.MX
  end
  if resolved.TXT then
    result.txt_records = resolved.TXT
  end
  if resolved.NS then
    result.ns_records = resolved.NS
  end

  if count == 0 then
    result.status = "empty"
    result.reason = "No records found for domain"
  end

  return result
end
