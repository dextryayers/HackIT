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
Attempts a full DNS zone transfer (AXFR) from the target nameserver to enumerate all
DNS records in the zone. Zone transfers are used by secondary DNS servers to replicate
zone data. A misconfigured nameserver may allow unrestricted AXFR, exposing all DNS
records including internal hostnames, IP addresses, service locations, and mail
exchange configurations. Tests multiple zone name candidates including the target
hostname, reverse DNS derived names, and common variations. Returns all discovered
records categorized by type (A, AAAA, MX, TXT, CNAME, NS, PTR, SRV, SOA). Use with
caution as zone transfers can generate significant traffic.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(53, "domain")

local function try_axfr(host, zone_name, port_num)
  local ok, records = pcall(dns.zone_transfer, host.ip, zone_name, port_num, 20000)
  if not ok or not records or #records == 0 then return nil end
  local parsed = {}
  for _, record in ipairs(records) do
    if type(record) == "table" then
      insert(parsed, {
        name = record.name or "?",
        type = record.dtype or "?",
        data = record.data or stdnse.tojson(record),
        ttl = record.ttl or 0
      })
    elseif type(record) == "string" then
      insert(parsed, { data = record })
    end
  end
  return parsed
end

action = function(host, port)
  local result = output_table()
  local zone_candidates = {}

  if host.targetname and #host.targetname > 0 then
    insert(zone_candidates, host.targetname)
  end

  local ok, reverse = pcall(nmap.dns_reverse, host.ip)
  if ok and reverse then
    local parts = strsplit("%.", reverse)
    if #parts >= 2 then
      for i = 0, #parts - 2 do
        local start = #parts - i
        local z = concat(parts, ".", start)
        insert(zone_candidates, z)
      end
    end
    insert(zone_candidates, reverse)
  end

  local seen = {}
  local unique_zones = {}
  for _, z in ipairs(zone_candidates) do
    local key = lower(z):gsub("%.$", "")
    if not seen[key] then
      seen[key] = true
      insert(unique_zones, key)
    end
  end

  if #unique_zones == 0 then
    insert(unique_zones, host.ip)
  end

  result.status = "success"
  result.server = host.ip
  result.port = port.number

  local zone_found = false

  for _, zone_name in ipairs(unique_zones) do
    local records = try_axfr(host, zone_name, port.number)
    if records then
      result.zone = zone_name
      result.total_records = #records

      local categorized = {}
      for _, rec in ipairs(records) do
        local rtype = rec.type or "UNKNOWN"
        if not categorized[rtype] then categorized[rtype] = {} end
        categorized[rtype][#categorized[rtype] + 1] = rec
      end
      result.records_by_type = categorized
      result.zone_transfer_allowed = true
      zone_found = true
      break
    end
  end

  if not zone_found then
    result.zone_transfer_allowed = false
    result.zones_tested = unique_zones
    result.reason = "Zone transfer refused for all candidates"
  end

  return result
end
