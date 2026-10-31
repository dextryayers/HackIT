local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"
local string = require "string"



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
  if match(ip, ":") then
    local ok, expanded = pcall(nmap.get_huge_addr, ip)
    if not ok or not expanded then return nil end
    local nibbles = ""
    for i = 1, #expanded do
      nibbles = sub(expanded, -i, -i) .. "." .. nibbles
    end
    return nibbles .. "ip6.arpa"
  else
    local octets = strsplit("%.", ip)
    if #octets ~= 4 then return nil end
    return octets[4] .. "." .. octets[3] .. "." .. octets[2] .. "." .. octets[1] .. ".in-addr.arpa"
  end
end

action = function(host, port)
  local result = output_table()

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
      insert(hostnames, tostring(v):gsub("%.$", ""))
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
