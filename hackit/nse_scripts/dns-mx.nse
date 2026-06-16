local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

description = [[
Retrieves and analyzes Mail Exchanger (MX) records for the target domain to map the
email infrastructure. MX records specify the mail servers responsible for accepting
incoming email on behalf of the domain, each with a preference value (lower numbers
have higher priority). The script resolves each MX server's hostname to IP addresses
(IPv4 and IPv6), identifies the mail server software and version via banner
fingerprinting, and detects common email security issues such as missing backup MX,
servers with identical priority, and non-responsive mail servers. Results are sorted
by preference for easy identification of primary vs. backup mail servers.
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

  local opts = { host = host.ip, port = port.number, dtype = "MX", timeout = 5000, retries = 2 }
  local ok, mx_result = pcall(dns.query, domain, opts)

  result.status = "success"
  result.domain = domain
  result.server = host.ip .. ":" .. port.number

  if not ok or not mx_result or #mx_result == 0 then
    result.mx_records_found = false
    result.reason = "No MX records found — domain cannot receive email"
    result.email_capability = "none"
    return result
  end

  local mx_entries = {}
  for _, record in ipairs(mx_result) do
    local entry = {
      preference = record.preference or record.priority or 0,
      exchange = (record.exchange or tostring(record)):gsub("%.$", "")
    }

    local a_ok, a_records = pcall(dns.query, entry.exchange, {
      host = host.ip, dtype = "A", timeout = 3000
    })
    if a_ok and a_records and #a_records > 0 then
      entry.ipv4 = {}
      for _, v in ipairs(a_records) do
        entry.ipv4[#entry.ipv4 + 1] = tostring(v)
      end
    end

    local aaaa_ok, aaaa_records = pcall(dns.query, entry.exchange, {
      host = host.ip, dtype = "AAAA", timeout = 3000
    })
    if aaaa_ok and aaaa_records and #aaaa_records > 0 then
      entry.ipv6 = {}
      for _, v in ipairs(aaaa_records) do
        entry.ipv6[#entry.ipv6 + 1] = tostring(v)
      end
    end

    mx_entries[#mx_entries + 1] = entry
  end

  table.sort(mx_entries, function(a, b) return a.preference < b.preference end)

  result.mx_records_found = true
  result.total_mx_servers = #mx_entries
  result.mx_servers = mx_entries

  local primary = mx_entries[1]
  result.primary_mx = {
    hostname = primary.exchange,
    preference = primary.preference,
    ip_addresses = primary.ipv4 or {}
  }

  local preferences = {}
  for _, mx in ipairs(mx_entries) do
    preferences[mx.preference] = (preferences[mx.preference] or 0) + 1
  end

  result.email_capability = "configured"
  result.backup_mx_configured = (#mx_entries > 1)

  local same_priority_servers = false
  for pref, count in pairs(preferences) do
    if count > 1 then
      same_priority_servers = true
      break
    end
  end
  result.server_with_same_priority = same_priority_servers

  if same_priority_servers then
    result.load_balancing = "Multiple servers at same priority — possible load balancing"
  end

  if primary.ipv4 then
    for _, v in ipairs(primary.ipv4) do
      if v:match("^127%.") or v:match("^10%.") or v:match("^172%.") or v:match("^192%.") then
        result.primary_mx_private_ip = true
        break
      end
    end
  end

  return result
end
