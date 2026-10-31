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
local msleep = function(ms)
    if stdnse and stdnse.sleep then
        return stdnse.sleep((ms or 0) / 1000)
    end
    if nmap.msleep then
        return nmap.msleep(ms or 0)
    end
    local deadline = nmap.clock() + (ms or 0) / 1000
    while nmap.clock() < deadline do end
    return true
end
local new_socket = nmap.new_socket
local resolve = nmap.resolve

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    if stdnse and stdnse.sleep then
        return stdnse.sleep(seconds)
    end
    if nmap.msleep then
        return nmap.msleep(math.max(0, math.floor((seconds or 0) * 1000)))
    end
    local deadline = nmap.clock() + (seconds or 0)
    while nmap.clock() < deadline do end
    return true
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
Analyzes the TCP timestamp option (RFC 1323) behavior of the target host in detail.
Extracts timestamp values from multiple SYN/ACK packets across separate TCP connections
to determine the timestamp granularity, update frequency, and increment pattern.
Tests both inter-connection and intra-connection timestamp behavior. Classifies the
counter as: per-packet (changes each packet), per-interval (ticks at fixed rate), or
per-connection (resets each connection). Granularity estimation identifies the TCP
stack implementation: Linux typically uses 1-10ms granularity, Windows uses ~100ms,
and some embedded systems use 1-second granularity. Useful for OS fingerprinting
and remote clock analysis.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

action = function(host, port)
  local result = output_table()
  local ts_samples = {}
  local sample_count = 12

  for i = 1, sample_count do
    local sock = new_socket("tcp")
    sock:set_timeout(3000)
    local ok, err = sock:connect(host.ip, port.number, "tcp")
    if ok then
      local info = sock:get_info()
      sock:close()
      if type(info)=="table" and info.timestamp and info.timestamp.tsval then
        insert(ts_samples, tonumber(info.timestamp.tsval) or 0)
      end
    else
      sock:close()
    end
    msleep(100)
  end

  if #ts_samples < 3 then
    result.status = "error"
    result.target = host.ip .. ":" .. port.number
    result.reason = "Insufficient TCP timestamp samples"
    return result
  end

  local intervals = {}
  for i = 2, #ts_samples do
    local diff = ts_samples[i] - ts_samples[i - 1]
    if diff >= 0 then
      insert(intervals, diff)
    end
  end

  if #intervals == 0 then
    result.status = "error"
    result.target = host.ip .. ":" .. port.number
    result.reason = "All timestamps were identical (static counter)"
    return result
  end

  local min_int = math.min(table.unpack(intervals))
  local max_int = math.max(table.unpack(intervals))
  local sum = 0
  for _, v in ipairs(intervals) do
    sum = sum + v
  end
  local avg_int = sum / #intervals

  local variance = 0
  for _, v in ipairs(intervals) do
    variance = variance + (v - avg_int) * (v - avg_int)
  end
  variance = variance / #intervals
  local std_dev = math.sqrt(variance)

  local frequency_hz
  local granularity_description
  if avg_int > 900 then
    frequency_hz = "~1 Hz"
    granularity_description = "1 second"
  elseif avg_int > 90 then
    frequency_hz = "~10 Hz"
    granularity_description = "100 ms"
  elseif avg_int > 9 then
    frequency_hz = "~100 Hz"
    granularity_description = "10 ms"
  elseif avg_int > 0.9 then
    frequency_hz = "~1000 Hz"
    granularity_description = "1 ms"
  elseif avg_int > 0.09 then
    frequency_hz = "~10000 Hz"
    granularity_description = "100 us"
  else
    frequency_hz = "> 10000 Hz"
    granularity_description = "Sub-millisecond / per-packet"
  end

  local increment_pattern
  if max_int == 0 then
    increment_pattern = "static"
  elseif max_int == min_int then
    increment_pattern = "strictly_linear"
  elseif std_dev < avg_int * 0.2 then
    increment_pattern = "approximately_linear"
  else
    increment_pattern = "non_linear"
  end

  result.status = "success"
  result.target = host.ip .. ":" .. port.number
  result.samples = #ts_samples
  result.timestamp_values = ts_samples
  result.intervals = intervals
  result.min_interval = min_int
  result.max_interval = max_int
  result.average_interval = format("%.2f", avg_int)
  result.standard_deviation = format("%.2f", std_dev)
  result.estimated_frequency = frequency_hz
  result.granularity = granularity_description
  result.increment_pattern = increment_pattern

  if increment_pattern == "strictly_linear" then
    result.tcp_stack_trait = "Consistent timer-based timestamp"
  elseif increment_pattern == "approximately_linear" then
    result.tcp_stack_trait = "Timer-based with minor jitter"
  elseif increment_pattern == "non_linear" then
    result.tcp_stack_trait = "Non-deterministic (per-packet or randomized)"
  else
    result.tcp_stack_trait = "Static timestamp (single value reused)"
  end

  return result
end
