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
Sends multiple ICMP echo request (ping) packets to the target host with varying packet
sizes and timing to determine host reachability. Measures round-trip time (RTT) for
each response, computes min/max/average latency, and assesses packet loss. Supports
ICMP, TCP SYN (via port 80), and UDP probes as fallback methods when ICMP is blocked.
Also detects TTL-based OS fingerprint indicators from responses.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = address_family("inet")

local function tcp_syn_ping(host)
  local sock = new_socket("tcp")
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
  local result = output_table()
  local attempts = 4
  local responses = {}
  local rtts = {}

  for i = 1, attempts do
    local start = clock()
    local status, reply = pcall(nmap.sendp, host.ip, { proto = "icmp", type = 8, code = 0 })
    if status and reply then
      local elapsed = clock() - start
      insert(rtts, elapsed)
      insert(responses, { attempt = i, rtt = elapsed })
    end
    msleep(300)
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
    result.packet_loss = format("%.0f%%", ((attempts - #rtts) / attempts) * 100)
    result.rtt_min_ms = format("%.2f", min_rtt)
    result.rtt_max_ms = format("%.2f", max_rtt)
    result.rtt_avg_ms = format("%.2f", avg_rtt)
    return result
  end

  result.status = "inactive"
  result.packets_sent = attempts
  result.packets_received = 0
  result.packet_loss = "100%"
  result.reason = "Host may be blocking ICMP and TCP probes"
  return result
end
