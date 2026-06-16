local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local math = require "math"

description = [[
Detects clock skew between the scanning host and the target system by comparing TCP
timestamp options (RFC 1323) in SYN/ACK responses over time. Multiple samples are
collected across a time window to establish a baseline and compute the average skew
rate. Clock skew detection can be useful for identifying virtual machines (VMs often
have different skew patterns), determining host relationships (same OS/uptime group),
detecting honeypots (simulated clocks), and OS fingerprinting. Reports skew in both
absolute ms and rate (s/s), with direction indication.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

action = function(host, port)
  local result = stdnse.output_table()
  local samples = {}
  local sample_count = 8

  for i = 1, sample_count do
    local sock = nmap.new_socket("tcp")
    sock:set_timeout(3000)
    local local_before = nmap.clock()
    local ok, err = sock:connect(host.ip, port.number, "tcp")
    local local_after = nmap.clock()

    if ok then
      local info = sock:get_info()
      sock:close()
      if info and info.timestamp and info.timestamp.tsval then
        samples[#samples + 1] = {
          remote_ts = tonumber(info.timestamp.tsval) or 0,
          local_ts = (local_before + local_after) / 2
        }
      end
    else
      sock:close()
    end
    nmap.msleep(500)
  end

  if #samples < 2 then
    result.status = "error"
    result.target = host.ip .. ":" .. port.number
    result.reason = "Insufficient TCP timestamp samples for clock skew analysis"
    return result
  end

  local total_skew = 0
  local skew_samples = 0
  for i = 2, #samples do
    local dt_remote = samples[i].remote_ts - samples[i - 1].remote_ts
    local dt_local = (samples[i].local_ts - samples[i - 1].local_ts) * 1000
    if dt_remote > 0 and dt_local > 0 then
      local skew = dt_remote - dt_local
      total_skew = total_skew + skew
      skew_samples = skew_samples + 1
    end
  end

  if skew_samples == 0 then
    result.status = "error"
    result.target = host.ip .. ":" .. port.number
    result.reason = "Could not compute clock skew (all timestamps identical)"
    return result
  end

  local avg_skew_ms = total_skew / skew_samples
  local avg_skew_sec = avg_skew_ms / 1000
  local total_elapsed = (samples[#samples].local_ts - samples[1].local_ts) * 1000
  local skew_rate = total_elapsed > 0 and (total_skew / total_elapsed) or 0

  local direction
  if math.abs(avg_skew_sec) < 0.5 then
    direction = "synchronized"
  elseif avg_skew_sec > 0 then
    direction = "remote clock is faster"
  else
    direction = "remote clock is slower"
  end

  result.status = "success"
  result.target = host.ip .. ":" .. port.number
  result.samples_collected = #samples
  result.skew_samples_used = skew_samples
  result.average_skew_ms = string.format("%.2f", avg_skew_ms)
  result.average_skew_sec = string.format("%.6f", avg_skew_sec)
  result.skew_rate = string.format("%.6f", skew_rate)
  result.direction = direction

  if math.abs(avg_skew_sec) > 10 then
    result.skew_magnitude = "large"
    result.note = "Large clock skew detected - possible VM or clock drift"
  elseif math.abs(avg_skew_sec) > 1 then
    result.skew_magnitude = "moderate"
    result.note = "Moderate clock skew detected"
  else
    result.skew_magnitude = "small"
    result.note = "Clocks are reasonably synchronized"
  end

  return result
end
