local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"
local string = require "string"

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
      entries[#entries + 1] = tostring(v)
    end
    return entries
  end
  return nil
end

action = function(host, port)
  local result = stdnse.output_table()

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
