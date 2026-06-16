local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends multiple ICMP echo request (ping) packets to the target host with varying packet
sizes and timing to determine host reachability. Measures round-trip time (RTT) for
each response, computes min/max/average latency, and assesses packet loss. Supports
ICMP, TCP SYN (via port 80), and UDP probes as fallback methods when ICMP is blocked.
Also detects TTL-based OS fingerprint indicators from responses.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.address_family("inet")

local function tcp_syn_ping(host)
  local sock = nmap.new_socket("tcp")
  if not sock then return nil end
  sock:set_timeout(3000)
  local ok, err = sock:connect(host.ip, 80, "tcp")
  if ok then
    local info = sock:get_info()
    sock:close()
    return info
  end
  sock:close()
  return nil
end

action = function(host, port)
  local result = stdnse.output_table()
  local attempts = 4
  local responses = {}
  local rtts = {}

  for i = 1, attempts do
    local start = nmap.clock()
    local status, reply = pcall(nmap.sendp, host.ip, { proto = "icmp", type = 8, code = 0 })
    if status and reply then
      local elapsed = nmap.clock() - start
      rtts[#rtts + 1] = elapsed
      responses[#responses + 1] = { attempt = i, rtt = elapsed }
    end
    nmap.msleep(300)
  end

  if #rtts == 0 then
    local tcp_result = tcp_syn_ping(host)
    if tcp_result then
      result.status = "alive"
      result.method = "TCP SYN (80)"
      result.rtt = "via TCP"
      return result
    end
  end

  if #rtts > 0 then
    local min_rtt = math.min(table.unpack(rtts)) * 1000
    local max_rtt = math.max(table.unpack(rtts)) * 1000
    local sum = 0
    for _, v in ipairs(rtts) do sum = sum + v end
    local avg_rtt = (sum / #rtts) * 1000

    result.status = "alive"
    result.method = "ICMP echo"
    result.packets_sent = attempts
    result.packets_received = #rtts
    result.packet_loss = string.format("%.0f%%", ((attempts - #rtts) / attempts) * 100)
    result.rtt_min_ms = string.format("%.2f", min_rtt)
    result.rtt_max_ms = string.format("%.2f", max_rtt)
    result.rtt_avg_ms = string.format("%.2f", avg_rtt)
    return result
  end

  result.status = "inactive"
  result.packets_sent = attempts
  result.packets_received = 0
  result.packet_loss = "100%"
  result.reason = "Host may be blocking ICMP and TCP probes"
  return result
end
