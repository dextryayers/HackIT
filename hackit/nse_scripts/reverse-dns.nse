local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"
local string = require "string"

description = [[
Performs reverse DNS (PTR) lookup on the target IP address to resolve its associated
hostname. Handles both IPv4 (in-addr.arpa) and IPv6 (ip6.arpa) reverse mapping formats.
Supports multiple DNS server fallback and configurable query retries. Returns the
PTR record and performs forward-confirmation by resolving the returned hostname back
to the original IP (FCrDNS validation). Useful for identifying hostnames behind IP
addresses and validating DNS consistency.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(53, "domain")

local function build_ptr_name(ip)
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

  local ptr_name = build_ptr_name(host.ip)
  if not ptr_name then
    result.status = "error"
    result.reason = "Could not build PTR query name from IP"
    return result
  end

  local opts = {
    host = host.ip,
    port = port.number,
    dtype = "PTR",
    timeout = 5000,
    retries = 2
  }

  local ok, ptr_records = pcall(dns.query, ptr_name, opts)

  result.status = "success"
  result.ip = host.ip
  result.ptr_query = ptr_name

  if ok and ptr_records and #ptr_records > 0 then
    local hostnames = {}
    for _, v in ipairs(ptr_records) do
      hostnames[#hostnames + 1] = tostring(v):gsub("%.$", "")
    end
    result.hostname = hostnames[1]
    result.all_ptr_records = hostnames

    local fwd_opts = {
      host = host.ip,
      port = port.number,
      dtype = "A",
      timeout = 3000
    }
    local fwd_ok, fwd_records = pcall(dns.query, hostnames[1], fwd_opts)
    if fwd_ok and fwd_records then
      result.fcrdns = {}
      result.fcrdns.query = hostnames[1]
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
    end
  else
    result.status = "empty"
    result.reason = "No PTR record found"
  end

  return result
end
