local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local packet = require "packet"

description = [[
Discovers live hosts on the local network by sending ICMP echo requests to the subnet
broadcast address. Listens for ICMP echo replies from multiple hosts on the local
network segment using raw socket capture. Automatically calculates the broadcast
address from the local interface's IP and netmask. Reports discovered hosts with
their IP and MAC addresses. Supports multiple probe rounds with configurable listen
time for improved coverage in noisy environments.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.address_family("inet")

local function calculate_broadcast(ip, netmask)
  local addr_parts = stdnse.strsplit("%.", ip)
  local mask_parts = stdnse.strsplit("%.", netmask)
  if #addr_parts ~= 4 or #mask_parts ~= 4 then return nil end
  local broadcast_parts = {}
  for i = 1, 4 do
    local addr_octet = tonumber(addr_parts[i]) or 0
    local mask_octet = tonumber(mask_parts[i]) or 0
    broadcast_parts[i] = addr_octet | (mask_octet ~ 0xFF) & 0xFF
  end
  return table.concat(broadcast_parts, ".")
end

action = function(host, port)
  local result = stdnse.output_table()
  local iface = nmap.get_interface_info()

  if not iface then
    result.status = "error"
    result.reason = "Could not determine network interface"
    return result
  end

  local netmask = iface.netmask or "255.255.255.0"
  local local_ip = iface.address or iface.ip or host.ip
  local broadcast_ip = calculate_broadcast(local_ip, netmask)

  if not broadcast_ip then
    result.status = "error"
    result.reason = "Failed to calculate broadcast address"
    return result
  end

  local discovered_hosts = {}

  for round = 1, 2 do
    local capture = nmap.pcap_open(broadcast_ip, 1, 65600, "icmp")
    if not capture then
      if round == 1 then
        nmap.msleep(500)
      end
      goto continue
    end

    local icmp_pkt = nmap.packet_build_icmp_echo(broadcast_ip)
    nmap.sendp(icmp_pkt, { dst = broadcast_ip })

    local deadline = nmap.clock() + 3
    while nmap.clock() < deadline do
      local ok, data = capture:receive()
      if ok and data then
        local pkt = packet.Packet:new(data)
        if pkt and pkt.ip_src and pkt.ip_src ~= "0.0.0.0" and pkt.ip_src ~= broadcast_ip and pkt.ip_src ~= local_ip then
          if not discovered_hosts[pkt.ip_src] then
            discovered_hosts[pkt.ip_src] = {
              ip = pkt.ip_src,
              mac = pkt.eth_src or "N/A",
              discovered_in_round = round
            }
          end
        end
      end
    end
    capture:close()
    ::continue::
  end

  local host_list = {}
  for ip_addr, info in pairs(discovered_hosts) do
    host_list[#host_list + 1] = info
  end
  table.sort(host_list, function(a, b) return a.ip < b.ip end)

  result.status = "success"
  result.broadcast_address = broadcast_ip
  result.interface = iface.device or "unknown"

  if #host_list > 0 then
    result.hosts_found = #host_list
    result.hosts = host_list
    result.probes_sent = 2
  else
    result.hosts_found = 0
    result.reason = "No hosts responded to broadcast ping"
  end

  return result
end
