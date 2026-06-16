local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

description = [[
Compares forward DNS (A record) and reverse DNS (PTR record) mappings to validate
DNS consistency for the target IP address and hostname. Performs Forward-Confirmed
Reverse DNS (FCrDNS) validation by: (1) resolving the target hostname to IP addresses
via A/AAAA records, (2) performing reverse lookup on the target IP to get PTR
hostname, (3) resolving the PTR hostname back to IP addresses, and (4) comparing
both directions. Identifies discrepancies indicating misconfigurations, DNS
spoofing, or load-balanced infrastructure. Consistent FCrDNS is critical for email
deliverability (anti-spam), TLS certificate validation, and SSH host key verification.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(53, "domain")

local function ptr_name_for_ip(ip)
  if ip:match(":") then
    local ok, expanded = pcall(nmap.get_huge_addr, ip)
    if not ok or not expanded then return nil end
    local nibbles = ""
    for i = 1, #expanded do
      nibbles = string.sub(expanded, -i, -i) .. "." .. nibbles
    end
    return nibbles .. "ip6.arpa"
  else
    local octets = stdnse.strsplit("%.", ip)
    if #octets ~= 4 then return nil end
    return octets[4] .. "." .. octets[3] .. "." .. octets[2] .. "." .. octets[1] .. ".in-addr.arpa"
  end
end

action = function(host, port)
  local result = stdnse.output_table()

  if not host.ip then
    result.status = "error"
    result.reason = "No target IP address available"
    return result
  end

  result.status = "success"
  result.ip = host.ip
  result.server = host.ip

  if host.targetname and #host.targetname > 0 then
    result.forward_name = host.targetname
    local a_opts = { host = host.ip, dtype = "A", timeout = 5000 }
    local ok, a_records = pcall(dns.query, host.targetname, a_opts)
    if ok and a_records and #a_records > 0 then
      result.forward_resolves_to = {}
      for _, v in ipairs(a_records) do
        result.forward_resolves_to[#result.forward_resolves_to + 1] = tostring(v)
      end
      local match = false
      for _, v in ipairs(a_records) do
        if tostring(v) == host.ip then
          match = true
          break
        end
      end
      result.forward_matches_target = match
    else
      result.forward_resolves_to = {}
      result.forward_matches_target = false
      result.forward_missing = true
    end
  end

  local ptr_name = ptr_name_for_ip(host.ip)
  if ptr_name then
    result.ptr_query = ptr_name
    local ptr_opts = { host = host.ip, dtype = "PTR", timeout = 5000 }
    local ok, ptr_records = pcall(dns.query, ptr_name, ptr_opts)
    if ok and ptr_records and #ptr_records > 0 then
      local ptr_hostnames = {}
      for _, v in ipairs(ptr_records) do
        ptr_hostnames[#ptr_hostnames + 1] = tostring(v):gsub("%.$", "")
      end
      result.ptr_hostname = ptr_hostnames[1]
      result.ptr_hostnames = ptr_hostnames

      local fcrdns_opts = { host = host.ip, dtype = "A", timeout = 5000 }
      local fwd_ok, fwd_records = pcall(dns.query, ptr_hostnames[1], fcrdns_opts)
      if fwd_ok and fwd_records then
        result.fcrdns = {}
        result.fcrdns.lookup = ptr_hostnames[1]
        result.fcrdns.resolves_to = {}
        for _, v in ipairs(fwd_records) do
          result.fcrdns.resolves_to[#result.fcrdns.resolves_to + 1] = tostring(v)
        end
        local match = false
        for _, v in ipairs(fwd_records) do
          if tostring(v) == host.ip then
            match = true
            break
          end
        end
        result.fcrdns.valid = match
        result.fcrdns_valid = match
      end
    else
      result.ptr_missing = true
    end
  end

  result.consistency_score = 0
  local checks = 0

  if result.forward_matches_target then
    result.consistency_score = result.consistency_score + 1
  end
  checks = checks + 1

  if result.ptr_hostname then
    result.consistency_score = result.consistency_score + 1
  end
  checks = checks + 1

  if result.fcrdns and result.fcrdns.valid then
    result.consistency_score = result.consistency_score + 2
  end
  checks = checks + 2

  result.consistency_score = string.format("%d/%d", result.consistency_score, checks)

  if result.fcrdns and result.fcrdns.valid then
    result.assessment = "FCrDNS passes — DNS configuration is consistent"
  elseif result.ptr_hostname then
    result.assessment = "Reverse record exists but FCrDNS fails — possible misconfiguration"
  else
    result.assessment = "No reverse DNS record found"
  end

  return result
end
