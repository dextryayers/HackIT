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
Probes the target DNS server with a comprehensive set of DNS query types to determine
which record types are supported and which return data. Tests over 25 different
resource record types including standard types (A, AAAA, MX, NS, SOA, TXT, CNAME, PTR),
infrastructure types (SRV, SSHFP, LOC, HINFO, RP, NAPTR), DNSSEC-related types
(DNSKEY, DS, RRSIG, NSEC, NSEC3, TLSA), security types (CAA, IPSECKEY), and
forwarding types (DNAME, ALIAS). Each type is tested against the target domain and
the response status (success, no data, or error) is recorded. Useful for assessing
DNS server capabilities and DNSSEC support.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(53, "domain")

local query_types = {
  "A", "AAAA", "MX", "NS", "SOA", "TXT", "CNAME",
  "PTR", "SRV", "CAA", "DNSKEY", "DS", "RRSIG",
  "NSEC", "NSEC3", "TLSA", "SSHFP", "LOC", "HINFO",
  "RP", "NAPTR", "DNAME", "ALIAS", "IPSECKEY", "APL",
  "SPF", "KEY", "SIG", "NXT", "CERT", "DHCID", "A6"
}

local type_categories = {
  standard = { "A", "AAAA", "MX", "NS", "SOA", "TXT", "CNAME", "PTR" },
  dnssec = { "DNSKEY", "DS", "RRSIG", "NSEC", "NSEC3", "TLSA", "KEY", "SIG", "NXT" },
  infrastructure = { "SRV", "SSHFP", "LOC", "HINFO", "RP", "NAPTR", "CERT", "DHCID" },
  forwarding = { "DNAME", "ALIAS", "A6" },
  security = { "CAA", "IPSECKEY", "SPF" },
  other = { "APL" }
}

action = function(host, port)
  local result = output_table()
  local domain = host.targetname

  if not domain or #domain == 0 then
    domain = "example.com"
  end

  local supported = {}
  local no_data = {}
  local failed = {}
  local base_opts = {
    host = host.ip,
    port = port.number,
    timeout = 3000,
    retries = 1
  }

  for _, qtype in ipairs(query_types) do
    local opts = {}
    for k, v in pairs(base_opts) do opts[k] = v end
    opts.dtype = qtype

    local ok, answer = pcall(dns.query, domain, opts)
    if ok and answer and #answer > 0 then
      insert(supported, {
        type = qtype,
        response_count = #answer
      })
    elseif ok and answer then
      insert(no_data, qtype)
    else
      insert(failed, qtype)
    end
  end

  result.status = "success"
  result.server = host.ip .. ":" .. port.number
  result.test_domain = domain
  result.total_types_tested = #query_types

  local categorized_support = {}
  for cat_name, types in pairs(type_categories) do
    local count = 0
    local found = {}
    for _, t in ipairs(types) do
      for _, s in ipairs(supported) do
        if s.type == t then
          count = count + 1
          insert(found, t)
          break
        end
      end
    end
    if count > 0 then
      categorized_support[cat_name] = {
        supported = count,
        total = #types,
        types = found
      }
    end
  end

  result.supported_types = supported
  result.supported_count = #supported
  result.supported_type_names = {}
  for _, s in ipairs(supported) do
    result.supported_type_names[#result.supported_type_names + 1] = s.type
  end

  result.no_data_types = no_data
  result.failed_types = failed
  result.dnssec_supported = false

  for _, s in ipairs(supported) do
    if s.type == "DNSKEY" or s.type == "DS" or s.type == "RRSIG" then
      result.dnssec_supported = true
      break
    end
  end

  result.support_categories = categorized_support

  return result
end
