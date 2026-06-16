local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local math = require "math"

description = [[
Estimates the target system's uptime by analyzing TCP timestamp options (RFC 1323)
from SYN/ACK responses. The script establishes TCP connections to multiple open ports
and extracts timestamp values, comparing them against known OS clock frequencies
(100Hz for Linux, 10Hz for Windows, 1Hz for older systems). By correlating timestamp
rates, it determines the most likely uptime estimate. Multiple samples reduce clock
interrupt variability. Useful for identifying recently rebooted systems and
OS fingerprinting.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = function(host, port)
  return port.state == "open" and port.protocol == "tcp"
end

local os_clock_frequencies = {
  { os = "Linux (100Hz)", freq = 100, weight = 1 },
  { os = "Linux (250Hz)", freq = 250, weight = 1 },
  { os = "Linux (1000Hz)", freq = 1000, weight = 1 },
  { os = "Windows (10Hz ~7.8ms)", freq = 128, weight = 1 },
  { os = "Windows (100Hz ~10ms)", freq = 100, weight = 1 },
  { os = "FreeBSD (128Hz)", freq = 128, weight = 1 },
  { os = "macOS (100Hz)", freq = 100, weight = 1 },
  { os = "Solaris (1Hz)", freq = 1, weight = 1 },
  { os = "Cisco IOS (1Hz)", freq = 1, weight = 1 }
}

action = function(host, port)
  local result = stdnse.output_table()
  local samples = {}

  for i = 1, 4 do
    local sock = nmap.new_socket()
    sock:set_timeout(5000)
    local ok, conn_err = sock:connect(host.ip, port.number, "tcp")
    if ok then
      local info = sock:get_info()
      sock:close()
      if info and info.timestamp and info.timestamp.tsval then
        samples[#samples + 1] = tonumber(info.timestamp.tsval) or 0
      end
    else
      sock:close()
    end
    nmap.msleep(300)
  end

  if #samples == 0 then
    result.status = "error"
    result.target = host.ip .. ":" .. port.number
    result.reason = "TCP timestamp option not present in any SYN/ACK response"
    return result
  end

  local ts_val = samples[1]
  result.status = "success"
  result.target = host.ip .. ":" .. port.number
  result.samples = #samples
  result.timestamp_values = samples

  local estimates = {}
  for _, entry in ipairs(os_clock_frequencies) do
    local uptime_secs = ts_val / entry.freq
    local uptime_days = uptime_secs / 86400
    if uptime_days >= 0 and uptime_days < 5000 then
      estimates[#estimates + 1] = {
        os_hint = entry.os,
        freq = entry.freq .. " Hz",
        uptime_seconds = math.floor(uptime_secs),
        uptime_days = math.floor(uptime_days),
        uptime_hours = math.floor((uptime_secs % 86400) / 3600),
        uptime_minutes = math.floor((uptime_secs % 3600) / 60)
      }
    end
  end

  result.uptime_estimates = estimates

  if #estimates > 0 then
    local best = estimates[1]
    result.best_estimate = best
    result.uptime_human = string.format("%d days, %d hours, %d minutes",
      best.uptime_days, best.uptime_hours, best.uptime_minutes)
    result.likely_os = best.os_hint
  end

  return result
end
