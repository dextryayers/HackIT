local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local math = require "math"



-- nmp function cache
local nmap_register = nmap.register_script
local nmap_settitle = nmap.set_title
local nmap_resolve = nmap.resolve
local nmap_get_port_state = nmap.get_port_state
local nmap_set_port_state = nmap.set_port_state
local comm = nmap.comm
local new_socket = nmap.new_socket
local get_timeout = nmap.get_timeout

-- Performance optimizations
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
local move = table.move or function(a1, f, e, t, a2)
    if not a2 then a2 = a1 end
    for i = f, e do a2[t + i - f] = a1[i] end
    return a2
end
local tostring = tostring
local tonumber = tonumber
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local unpack = unpack or table.unpack
local setmetatable = setmetatable
local getmetatable = getmetatable
local error = error
local select = select
local clock = nmap.clock
local msleep = nmap.msleep
local sleep = stdnse.sleep
local strsplit = stdnse.strsplit
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
      if info and info.timestamp and info.timestamp.tsval then
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
