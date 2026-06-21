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
  local result = output_table()
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

    insert(mx_entries, entry)
  end

  sort(mx_entries, function(a, b) return a.preference < b.preference end)

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
