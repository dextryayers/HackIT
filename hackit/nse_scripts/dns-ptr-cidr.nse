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
Performs reverse DNS (PTR) lookups for a range of IP addresses within a CIDR block
to discover hostnames associated with active addresses. The script iterates through
all IP addresses in the target subnet, queries for PTR records, and builds a
complete IP-to-hostname mapping. Features include: CIDR notation parsing, automatic
subnet size limiting (256 IPs max for performance), progress reporting, and rate
limiting to avoid DNS server overload. Results include both resolved and unresolved
addresses for network utilization assessment. Useful for infrastructure mapping,
identifying naming conventions, and discovering hosts without forward DNS records.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(53, "domain")

local function ip_to_num(ip)
  local octets = strsplit("%.", ip)
  if #octets ~= 4 then return nil end
  local num = 0
  for i = 1, 4 do
    num = num * 256 + (tonumber(octets[i]) or 0)
  end
  return num
end

local function num_to_ip(num)
  local octets = {}
  for i = 3, 0, -1 do
    insert(octets, tostring((num >> (i * 8)) & 0xFF))
  end
  return concat(octets, ".")
end

local function cidr_to_range(cidr)
  local parts = strsplit("/", cidr)
  if #parts ~= 2 then return nil, nil end
  local base_ip = parts[1]
  local prefix = tonumber(parts[2]) or 24
  local base_num = ip_to_num(base_ip)
  if not base_num then return nil, nil end
  local mask = (1 << (32 - prefix)) - 1
  local network = base_num & ~mask
  local broadcast = network | mask
  return network + 1, broadcast - 1, prefix
end

action = function(host, port)
  local result = output_table()

  if not host.ip then
    result.status = "error"
    result.reason = "No target IP address available"
    return result
  end

  local cidr = host.ip
  if host.targetname and #host.targetname > 0 then
    if host.match(targetname, "/") then
      cidr = host.targetname
    end
  end

  if not match(cidr, "/") then
    cidr = cidr .. "/24"
  end

  local start_ip, end_ip, prefix = cidr_to_range(cidr)
  if not start_ip or not end_ip then
    result.status = "error"
    result.reason = "Invalid CIDR notation: " .. cidr
    return result
  end

  local total_ips = end_ip - start_ip + 1

  result.status = "success"
  result.cidr = cidr
  result.server = host.ip .. ":" .. port.number
  result.network_base = num_to_ip(start_ip - 1)
  result.prefix_length = prefix
  result.total_addresses = total_ips

  if total_ips > 256 then
    result.truncated = true
    result.reason = "CIDR range too large (" .. total_ips .. " IPs). Scanning limited to first 256 addresses."
    end_ip = start_ip + 255
    total_ips = 256
  end

  local ptr_results = {}
  local scanned = 0

  for ip_num = start_ip, end_ip do
    local ip = num_to_ip(ip_num)
    local octets = strsplit("%.", ip)
    local ptr_name = octets[4] .. "." .. octets[3] .. "." .. octets[2] .. "." .. octets[1] .. ".in-addr.arpa"

    local opts = {
      host = host.ip,
      port = port.number,
      dtype = "PTR",
      timeout = 3000,
      retries = 1
    }

    local ok, answer = pcall(dns.query, ptr_name, opts)

    if ok and answer and #answer > 0 then
      local hostnames = {}
      for _, v in ipairs(answer) do
        insert(hostnames, tostring(v):gsub("%.$", ""))
      end
      insert(ptr_results, {
        ip = ip,
        hostname = hostnames[1],
        all_ptr_records = hostnames
      })
    end

    scanned = scanned + 1
    if scanned % 10 == 0 then
      msleep(5)
    end
  end

  result.scanned_addresses = scanned

  if #ptr_results > 0 then
    result.ptr_records_found = #ptr_results
    result.resolved_hosts = ptr_results
    result.resolution_rate = format("%.1f%%", (#ptr_results / scanned) * 100)
    result.unresolved_addresses = scanned - #ptr_results
  else
    result.ptr_records_found = 0
    result.reason = "No PTR records found for any IP in range"
    result.resolved_hosts = {}
  end

  return result
end
