local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"



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
Sends ARP requests to the target IP address to determine host aliveness on the local
subnet. Performs multiple ARP probes with configurable retries to detect hosts that
block ICMP or TCP probes. Returns MAC address, interface, and vendor information
for responsive hosts. Useful for host discovery in local network segments where
firewalls may filter other probe types.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.address_family("inet")

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
    local mac = reply.mac_addr:upper()
    local oui = mac:match("^([%x][%x]:[%x][%x]:[%x][%x])")
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
