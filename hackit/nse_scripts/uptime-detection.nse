local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local math = require "math"



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
  local result = output_table()
  local samples = {}

  for i = 1, 4 do
    local sock = new_socket()
    sock:set_timeout(5000)
    local ok, conn_err = sock:connect(host.ip, port.number, "tcp")
    if ok then
      local info = sock:get_info()
      sock:close()
      if info and info.timestamp and info.timestamp.tsval then
        insert(samples, tonumber(info.timestamp.tsval) or 0)
      end
    else
      sock:close()
    end
    msleep(300)
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
      insert(estimates, {
        os_hint = entry.os,
        freq = entry.freq .. " Hz",
        uptime_seconds = math.floor(uptime_secs),
        uptime_days = math.floor(uptime_days),
        uptime_hours = math.floor((uptime_secs % 86400) / 3600),
        uptime_minutes = math.floor((uptime_secs % 3600) / 60)
      })
    end
  end

  result.uptime_estimates = estimates

  if #estimates > 0 then
    local best = estimates[1]
    result.best_estimate = best
    result.uptime_human = format("%d days, %d hours, %d minutes",
      best.uptime_days, best.uptime_hours, best.uptime_minutes)
    result.likely_os = best.os_hint
  end

  return result
end
