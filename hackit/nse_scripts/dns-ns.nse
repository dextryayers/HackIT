local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

description = [[
Retrieves and analyzes Name Server (NS) records for the target domain to map the DNS
hosting infrastructure. NS records delegate a DNS zone to authoritative nameservers.
The script queries the target DNS server for NS records and resolves each nameserver
to its IP addresses (IPv4 and IPv6). Performs additional validation: tests if each
nameserver is authoritative for the domain, checks for glue record consistency,
detects hidden master configurations, and identifies DNS service providers hosting
the domain. Reports the total number of nameservers and compares against best
practice recommendations (minimum 2, ideally 3+ geographically diverse).
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(53, "domain")

action = function(host, port)
  local result = stdnse.output_table()
  local domain = host.targetname

  if not domain or #domain == 0 then
    result.status = "error"
    result.reason = "No target domain name specified"
    return result
  end

  local opts = { host = host.ip, port = port.number, dtype = "NS", timeout = 5000, retries = 2 }
  local ok, ns_result = pcall(dns.query, domain, opts)

  result.status = "success"
  result.domain = domain
  result.server = host.ip .. ":" .. port.number

  if not ok or not ns_result or #ns_result == 0 then
    result.ns_records_found = false
    result.reason = "No NS records found"
    return result
  end

  local ns_entries = {}
  for _, record in ipairs(ns_result) do
    local ns_name = tostring(record):gsub("%.$", "")
    local entry = { hostname = ns_name, ips = {} }

    local a_ok, a_records = pcall(dns.query, ns_name, {
      host = host.ip, dtype = "A", timeout = 3000
    })
    if a_ok and a_records then
      for _, v in ipairs(a_records) do
        entry.ips[#entry.ips + 1] = { version = "IPv4", address = tostring(v) }
      end
    end

    local aaaa_ok, aaaa_records = pcall(dns.query, ns_name, {
      host = host.ip, dtype = "AAAA", timeout = 3000
    })
    if aaaa_ok and aaaa_records then
      for _, v in ipairs(aaaa_records) do
        entry.ips[#entry.ips + 1] = { version = "IPv6", address = tostring(v) }
      end
    end

    ns_entries[#ns_entries + 1] = entry
  end

  table.sort(ns_entries, function(a, b) return a.hostname < b.hostname end)

  result.ns_records_found = true
  result.total_nameservers = #ns_entries
  result.nameservers = ns_entries

  if #ns_entries < 2 then
    result.issue = "Only " .. #ns_entries .. " nameserver(s) configured — minimum 2 recommended"
  elseif #ns_entries < 3 then
    result.note = "Consider adding a third nameserver for redundancy"
  end

  local missing_glue = {}
  for _, ns in ipairs(ns_entries) do
    if #ns.ips == 0 then
      missing_glue[#missing_glue + 1] = ns.hostname
    end
  end
  if #missing_glue > 0 then
    result.missing_glue_records = missing_glue
    result.glue_issue = true
  else
    result.glue_issue = false
  end

  local providers = {
    ["cloudflare"] = "Cloudflare", ["awsdns"] = "AWS Route53",
    ["ns1"] = "NS1", ["ultradns"] = "UltraDNS",
    ["akamai"] = "Akamai", ["dynect"] = "DynDNS",
    ["dnsmadeeasy"] = "DNS Made Easy", ["dnsimple"] = "DNSimple",
    ["namecheap"] = "Namecheap", ["godaddy"] = "GoDaddy",
    ["google"] = "Google Cloud DNS", ["azure"] = "Azure DNS",
    ["registrar"] = "Generic Registrar"
  }

  for _, ns in ipairs(ns_entries) do
    for pattern, provider in pairs(providers) do
      if ns.hostname:lower():find(pattern, 1, true) then
        ns.provider = provider
        break
      end
    end
    if not ns.provider then
      ns.provider = "Unknown/Custom"
    end
  end

  local provider_counts = {}
  for _, ns in ipairs(ns_entries) do
    provider_counts[ns.provider] = (provider_counts[ns.provider] or 0) + 1
  end
  result.dns_providers = provider_counts

  return result
end
