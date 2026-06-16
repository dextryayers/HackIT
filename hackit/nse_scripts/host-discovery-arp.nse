local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

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
      nmap.msleep(100)
    end
  end
  return nil
end

action = function(host, port)
  local result = stdnse.output_table()

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
