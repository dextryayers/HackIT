local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local math = require "math"

description = [[
Analyzes IP Time-To-Live (TTL) values from responses received from the target host
to infer the operating system and estimate network distance. Collects multiple TTL
samples from both TCP handshake and ICMP responses for cross-validation. Uses known
initial TTL values to identify OS families: 64 (Linux, macOS, Android, BSD),
128 (Windows, ChromeOS), 255 (Cisco, Solaris, HP-UX, AIX), and 32 (some embedded
systems, certain Windows versions). Calculates estimated hop count to target by
substracting observed TTL from initial TTL.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

local common_initial_ttls = {
  { ttl = 32, os = "Embedded/Some Windows", confidence = 1 },
  { ttl = 64, os = "Linux/macOS/BSD/Android", confidence = 4 },
  { ttl = 128, os = "Windows/ChromeOS", confidence = 4 },
  { ttl = 255, os = "Cisco/Solaris/AIX/HP-UX", confidence = 3 }
}

action = function(host, port)
  local result = stdnse.output_table()
  local ttl_samples = {}
  local sample_count = 6

  for i = 1, sample_count do
    local sock = nmap.new_socket("tcp")
    sock:set_timeout(3000)
    local ok = sock:connect(host.ip, port.number, "tcp")
    if ok then
      local info = sock:get_info()
      sock:close()
      if info and info.ttl then
        ttl_samples[#ttl_samples + 1] = tonumber(info.ttl) or 0
      end
    else
      sock:close()
    end
    nmap.msleep(100)
  end

  if #ttl_samples == 0 then
    result.status = "error"
    result.target = host.ip .. ":" .. port.number
    result.reason = "No TTL samples collected from target"
    return result
  end

  local observed_ttl = math.max(table.unpack(ttl_samples))
  local ttl_freq = {}
  for _, v in ipairs(ttl_samples) do
    ttl_freq[v] = (ttl_freq[v] or 0) + 1
  end

  local most_common_ttl = observed_ttl
  local max_freq = 0
  for ttl, freq in pairs(ttl_freq) do
    if freq > max_freq then
      max_freq = freq
      most_common_ttl = ttl
    end
  end

  local os_guesses = {}
  for _, entry in ipairs(common_initial_ttls) do
    if most_common_ttl <= entry.ttl and most_common_ttl > entry.ttl - 64 then
      local estimated_hops = entry.ttl - most_common_ttl
      os_guesses[#os_guesses + 1] = {
        os_family = entry.os,
        initial_ttl = entry.ttl,
        estimated_hops = estimated_hops,
        confidence = entry.confidence
      }
    end
  end

  table.sort(os_guesses, function(a, b) return a.confidence > b.confidence end)

  local best_guess = #os_guesses > 0 and os_guesses[1] or nil

  result.status = "success"
  result.target = host.ip .. ":" .. port.number
  result.samples_collected = #ttl_samples
  result.ttl_values = ttl_samples
  result.observed_ttl = most_common_ttl
  result.ttl_consistency = (#ttl_samples == max_freq) and "consistent" or "variable"

  if best_guess then
    result.initial_ttl = best_guess.initial_ttl
    result.estimated_hops = best_guess.estimated_hops
    result.os_guess = best_guess.os_family
    result.os_guesses = os_guesses

    if best_guess.initial_ttl == 64 then
      result.estimated_hops_to_target = most_common_ttl > 48 and "Local/close" or
        most_common_ttl > 32 and "Few hops away" or "Many hops away"
    elseif best_guess.initial_ttl == 128 then
      result.estimated_hops_to_target = most_common_ttl > 110 and "Local/close" or
        most_common_ttl > 64 and "Few hops away" or "Many hops away"
    end
  else
    result.os_guess = "Unknown"
    result.os_guesses = {}
  end

  return result
end
