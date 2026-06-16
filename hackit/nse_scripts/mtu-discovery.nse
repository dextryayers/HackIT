local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local packet = require "packet"
local string = require "string"

description = [[
Discovers the Path MTU (Maximum Transmission Unit) between the scanning host and the
target by sending ICMP echo requests with the Don't Fragment (DF) flag set and
varying payload sizes. Uses a binary search algorithm for efficient discovery instead
of linear stepping. When a packet exceeds the path MTU, the target or an intermediate
router sends an ICMP Fragmentation Needed (type 3, code 4) message. The largest
successful packet size determines the path MTU. Reports MTU, maximum payload size,
and identifies known MTU values (standard Ethernet 1500, jumbo frames 9000, VPN tunnel
issues, etc.).
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.address_family("inet")

action = function(host, port)
  local result = stdnse.output_table()
  local probe_socket = nmap.new_socket("raw", "icmp")
  if not probe_socket then
    result.status = "error"
    result.reason = "Could not create raw ICMP socket"
    return result
  end
  probe_socket:set_timeout(2000)

  local capture_socket = nmap.pcap_open(nil, nil, 1514, "icmp")
  if not capture_socket then
    probe_socket:close()
    result.status = "error"
    result.reason = "Could not open pcap for response capture"
    return result
  end

  local low = 68
  local high = 1500
  local discovered_mtu = nil

  while low <= high do
    local mid = math.floor((low + high) / 2)
    local payload_size = mid - 28
    if payload_size < 0 then break end

    local payload = string.rep("A", payload_size)
    local icmp_pkt = nmap.packet_build_icmp_echo(host.ip, nil, nil, payload)
    local sent = nmap.sendp(icmp_pkt, { dst = host.ip, df = true })

    if not sent then
      high = mid - 1
      nmap.msleep(100)
      goto continue
    end

    local responded = false
    local deadline = nmap.clock() + 2
    while nmap.clock() < deadline do
      local ok, data = capture_socket:receive()
      if ok and data then
        local reply = packet.Packet:new(data)
        if reply then
          local src_ip = reply.ip_src or ""
          local icmp_type = reply.mf or reply.ip_p
          if reply.ip_src == host.ip then
            responded = true
            discovered_mtu = mid
            low = mid + 1
            break
          end
        end
      end
    end

    if not responded then
      high = mid - 1
    end
    ::continue::
  end

  probe_socket:close()
  capture_socket:close()

  if discovered_mtu then
    local mtu_aligned = math.floor(discovered_mtu / 8) * 8
    local max_payload = discovered_mtu - 20 - 8
    local known_mtu_name = "Unknown"
    local known_mtus = {
      [576] = "Minimum IPv4", [1280] = "IPv6 minimum",
      [1492] = "PPPoE", [1500] = "Standard Ethernet",
      [1522] = "802.1Q VLAN", [4470] = "FDDI",
      [4352] = "FDDI extended", [9000] = "Jumbo frame (standard)",
      [9216] = "Jumbo frame (Cisco)"
    }
    known_mtu_name = known_mtus[discovered_mtu] or
                     known_mtus[mtu_aligned] or "Custom"

    result.status = "success"
    result.target = host.ip
    result.path_mtu = discovered_mtu
    result.mtu_aligned_8 = mtu_aligned
    result.max_payload_size = max_payload
    result.mtu_type = known_mtu_name
    result.search_method = "binary search"
    result.search_range = "68-1500 bytes"

    if discovered_mtu < 576 then
      result.warning = "MTU below IPv6 minimum (1280) and below IPv4 minimum (576)"
    elseif discovered_mtu < 1280 then
      result.warning = "MTU below IPv6 minimum (1280)"
    elseif discovered_mtu < 1500 then
      result.warning = "MTU below standard Ethernet (1500) - possible tunnel/VPN"
    end
  else
    result.status = "error"
    result.target = host.ip
    result.reason = "Could not determine path MTU. Target may not be reachable or DF-bit probes are not supported."
  end

  return result
end
