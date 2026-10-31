local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"



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
local new_socket = nmap.new_socket
local resolve = nmap.resolve

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

-- shortport.address_family is not part of the shortport API.
local address_family = function(af)
    return function(host, port) return nmap.address_family() == af end
end

description = [[
Sends ARP requests to the target IP address to determine host aliveness on the local
subnet. Performs multiple ARP probes with configurable retries to detect hosts that
block ICMP or TCP probes. Returns MAC address, interface, and vendor information
for responsive hosts. Useful for host discovery in local network segments where
firewalls may filter other probe types.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = address_family("inet")

local function probe_arp(target_ip, retries)
  for i = 1, retries do
    local reply = nmap.arp_query(target_ip, target_ip)
    if reply and reply.mac_addr then
      return reply
    end
    if i < retries then
      msleep(100)
    end
  end
  return nil
end

action = function(host, port)
  local result = output_table()

  local reply = probe_arp(host.ip, 3)
  if reply and reply.mac_addr then
    local mac = reply.upper(mac_addr)
    local oui = match(mac, "^([%x][%x]:[%x][%x]:[%x][%x])")
    result.status = "alive"
    result.ip = host.ip
    result.mac = mac
    result.interface = reply.interface or "unknown"
    result.vendor = reply.vendor or "Unknown"
    result.oui_prefix = oui or "N/A"
    result.probes_sent = 3
    result.probes_responded = 1
    return result
  end

  result.status = "inactive"
  result.ip = host.ip
  result.reason = "No ARP response received after 3 probes"
  return result
end
