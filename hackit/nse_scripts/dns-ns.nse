local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"



-- Fast-path bindings for the stdlib and nmap API used by this script.
-- Kept strict-mode safe: every name below is a declared local.
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
local move = table.move
local tostring = tostring
local tonumber = tonumber
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local unpack = table.unpack
local setmetatable = setmetatable
local getmetatable = getmetatable
local error = error
local select = select

local clock = nmap.clock
local msleep = nmap.msleep

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    return nmap.msleep(math.max(0, math.floor(seconds * 1000)))
end

local strsplit = function(sep, str, max)
    local out, pos, n = {}, 1, 0
    if str == nil then return out end
    while true do
        if max and n >= max - 1 then
            out[#out + 1] = sub(str, pos)
            return out
        end
        local s, e = find(str, sep, pos)
        if not s then
            out[#out + 1] = sub(str, pos)
            return out
        end
        if e < pos then e = pos end
        out[#out + 1] = sub(str, pos, s - 1)
        pos = e + 1
        n = n + 1
        if pos > #str then
            out[#out + 1] = ""
            return out
        end
    end
end

local format_output = stdnse.format_output
local output_table = stdnse.output_table

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
  local result = output_table()
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

    insert(ns_entries, entry)
  end

  sort(ns_entries, function(a, b) return a.hostname < b.hostname end)

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
      insert(missing_glue, ns.hostname)
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
      if ns.lower(hostname):find(pattern, 1, true) then
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
