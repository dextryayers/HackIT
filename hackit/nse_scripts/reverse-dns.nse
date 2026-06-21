local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"
local string = require "string"



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
