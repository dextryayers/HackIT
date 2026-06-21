local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
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
Analyzes the IP ID (Identification field) sequence generation of the target host by
sending a series of TCP SYN probes and observing the IP identification values in
responses. Classifies the sequence as incremental, random, constant, or time-based,
and determines suitability for idle scanning (zombie host assessment). Performs
statistical analysis including min/max/mean increment calculations. Uses multiple
sample sets with varying probe spacing to distinguish between per-packet and
per-connection counter behavior. Important for OS fingerprinting and idle scan
feasibility assessment.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

action = function(host, port)
  local result = output_table()
  local probes = 8
  local intervals = {}
  local prev_id = nil

  for i = 1, probes do
    local sock = new_socket("tcp")
    sock:set_timeout(3000)
    local ok, err = sock:connect(host.ip, port.number, "tcp")
    if ok then
      local info = sock:get_info()
      sock:close()
      if info and info.ip_id then
        local current_id = tonumber(info.ip_id)
        if current_id then
          if prev_id then
            local diff = current_id - prev_id
            if diff < 0 then diff = diff + 65536 end
            insert(intervals, diff)
          end
          prev_id = current_id
        end
      end
    else
      sock:close()
    end
    msleep(100)
  end

  if #intervals < 2 then
    result.status = "error"
    result.target = host.ip .. ":" .. port.number
    result.reason = "Insufficient IP ID samples collected"
    return result
  end

  local min_diff = math.min(table.unpack(intervals))
  local max_diff = math.max(table.unpack(intervals))
  local sum = 0
  for _, d in ipairs(intervals) do
    sum = sum + d
  end
  local avg_diff = sum / #intervals

  local variance = 0
  for _, d in ipairs(intervals) do
    variance = variance + (d - avg_diff) * (d - avg_diff)
  end
  variance = variance / #intervals
  local std_dev = math.sqrt(variance)

  local classification
  local score -- 0=constant, 1=predictable, 2=time-based, 3=random

  if max_diff == 0 then
    classification = "Constant"
    score = 0
  elseif max_diff <= 5 and avg_diff >= 0.5 then
    classification = "Incremental (predictable)"
    score = 1
  elseif max_diff <= 10 and avg_diff >= 0.5 then
    classification = "Mostly Incremental (some jitter)"
    score = 1
  elseif max_diff > 1000 and min_diff > 0 then
    classification = "Time-based"
    score = 2
  elseif max_diff > 1000 then
    classification = "Random"
    score = 3
  elseif std_dev > 1000 then
    classification = "Random (high variance)"
    score = 3
  elseif max_diff > 100 and std_dev > 50 then
    classification = "Broken Incremental (irregular)"
    score = 2
  else
    classification = "Mixed/Unknown"
    score = 2
  end

  result.status = "success"
  result.target = host.ip .. ":" .. port.number
  result.samples_collected = #intervals
  result.min_increment = min_diff
  result.max_increment = max_diff
  result.avg_increment = format("%.2f", avg_diff)
  result.standard_deviation = format("%.2f", std_dev)
  result.classification = classification
  result.idle_scan_usable = (score <= 1)
  result.intervals = intervals

  if score <= 1 then
    result.idle_scan_note = "Host is suitable as zombie for idle scan"
  elseif score == 2 then
    result.idle_scan_note = "Host may be usable with some prediction uncertainty"
  else
    result.idle_scan_note = "Host is NOT suitable for idle scanning"
  end

  return result
end
