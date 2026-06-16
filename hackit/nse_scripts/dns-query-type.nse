local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

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
  local result = stdnse.output_table()
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
      supported[#supported + 1] = {
        type = qtype,
        response_count = #answer
      }
    elseif ok and answer then
      no_data[#no_data + 1] = qtype
    else
      failed[#failed + 1] = qtype
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
          found[#found + 1] = t
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
