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
Performs NSEC (Next Secure) record zone walking against DNSSEC-signed zones that use
NSEC records (as opposed to NSEC3 with opt-out). When DNSSEC is enabled with NSEC,
it is possible to enumerate all record names in the zone by following the chain of
NSEC records, as each NSEC record points to the next existing record name in
canonical order. This reveals all domain names in the zone, defeating the purpose of
DNSSEC's authenticated denial of existence. The script follows the NSEC chain up to
a configurable maximum iterations and categorizes discovered record types. Useful for
assessing DNSSEC deployment privacy implications.
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

  local domain_count = 0
  local current_owner = domain
  local discovered = {}
  local max_iterations = 300
  local base_opts = {
    host = host.ip,
    port = port.number,
    dtype = "NSEC",
    timeout = 5000,
    retries = 1
  }

  for i = 1, max_iterations do
    local ok, nsec_result = pcall(dns.query, current_owner, base_opts)

    if not ok or not nsec_result or #nsec_result == 0 then
      break
    end

    local next_owner = nil
    local record_types = {}

    for _, record in ipairs(nsec_result) do
      if type(record) == "table" then
        if record.next_domain then
          next_owner = record.next_domain
        end
        if record.types and type(record.types) == "table" then
          record_types = record.types
        end
      end
    end

    if not next_owner then
      if type(nsec_result[1]) == "table" then
        next_owner = nsec_result[1].next or nsec_result[1].next_domain
      else
        next_owner = tostring(nsec_result[1])
      end
    end

    if not next_owner or next_owner == current_owner then
      break
    end

    local normalized_next = lower(next_owner):gsub("%.$", "")
    local normalized_current = lower(current_owner):gsub("%.$", "")

    if not discovered[normalized_current] then
      discovered[normalized_current] = {
        owner = normalized_current,
        record_types = record_types
      }
      domain_count = domain_count + 1
    end

    if normalized_next <= normalized_current then
      break
    end

    current_owner = next_owner

    if domain_count >= max_iterations then
      break
    end
  end

  result.status = "success"
  result.domain = domain
  result.server = host.ip .. ":" .. port.number
  result.nsec_walk_possible = (domain_count > 0)

  if domain_count > 0 then
    result.domains_discovered = domain_count
    result.walk_limit = max_iterations

    local sorted = {}
    for d, info in pairs(discovered) do
      insert(sorted, info)
    end
    sort(sorted, function(a, b) return a.owner < b.owner end)
    result.records = sorted

    local all_types = {}
    for _, info in ipairs(sorted) do
      if info.record_types then
        for _, t in ipairs(info.record_types) do
          all_types[t] = (all_types[t] or 0) + 1
        end
      end
    end
    result.record_type_distribution = all_types

    result.privacy_assessment = {
      nsec_vulnerability = "Zone uses NSEC (not NSEC3) - all records enumerable",
      recommendation = "Consider migrating to NSEC3 with opt-out to prevent zone walking",
      exposed_record_count = domain_count
    }
  else
    result.domains_discovered = 0
    result.reason = "NSEC walking not possible. Zone may use NSEC3, DNSSEC not enabled, or server blocks NSEC queries."
    result.privacy_assessment = {
      nsec_vulnerability = "Zone appears resistant to NSEC walking"
    }
  end

  return result
end
