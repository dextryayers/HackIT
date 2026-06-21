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
Analyzes the TCP Initial Sequence Number (ISN) generation pattern of the target host
by collecting multiple SYN/ACK responses and measuring deltas between successive
sequence numbers. Performs statistical analysis including min/max/mean increments,
standard deviation, and variance to classify the ISN randomness. Assesses TCP
sequence number prediction difficulty for OS fingerprinting and TCP hijacking risk
evaluation. Classes range from "Very Easy" (predictable, e.g., older Windows) to
"Very Hard" (truly random, e.g., modern Linux with random ISN generation).
Collects 8+ samples with configurable inter-probe spacing for reliability.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

action = function(host, port)
  local result = output_table()
  local samples = {}
  local sample_count = 10

  for i = 1, sample_count do
    local sock = new_socket("tcp")
    sock:set_timeout(4000)
    local ok, err = sock:connect(host.ip, port.number, "tcp")
    if ok then
      local info = sock:get_info()
      sock:close()
      if info and info.seq then
        local seq_num = tonumber(info.seq)
        if seq_num then
          insert(samples, seq_num)
        end
      end
    else
      sock:close()
    end
    msleep(200)
  end

  if #samples < 3 then
    result.status = "error"
    result.target = host.ip .. ":" .. port.number
    result.reason = "Insufficient TCP sequence samples collected"
    return result
  end

  local diffs = {}
  for i = 2, #samples do
    local diff = samples[i] - samples[i - 1]
    if diff < 0 then diff = diff + 4294967296 end
    insert(diffs, diff)
  end

  local min_diff = math.min(table.unpack(diffs))
  local max_diff = math.max(table.unpack(diffs))
  local sum = 0
  for _, d in ipairs(diffs) do
    sum = sum + d
  end
  local avg_diff = sum / #diffs

  local variance = 0
  for _, d in ipairs(diffs) do
    variance = variance + (d - avg_diff) * (d - avg_diff)
  end
  variance = variance / #diffs
  local std_dev = math.sqrt(variance)

  local difficulty_level
  if std_dev < 100 then
    difficulty_level = "Very Easy"
  elseif std_dev < 1000 then
    difficulty_level = "Easy"
  elseif std_dev < 10000 then
    difficulty_level = "Moderate"
  elseif std_dev < 100000 then
    difficulty_level = "Hard"
  else
    difficulty_level = "Very Hard"
  end

  local s_range = max_diff - min_diff
  local tcp_sequence_grade
  if difficulty_level == "Very Easy" then
    tcp_sequence_grade = "POOR (predictable ISN)"
  elseif difficulty_level == "Easy" then
    tcp_sequence_grade = "LOW (somewhat predictable)"
  elseif difficulty_level == "Moderate" then
    tcp_sequence_grade = "MODERATE"
  elseif difficulty_level == "Hard" then
    tcp_sequence_grade = "GOOD"
  else
    tcp_sequence_grade = "EXCELLENT (random ISN)"
  end

  result.status = "success"
  result.target = host.ip .. ":" .. port.number
  result.samples_collected = #samples
  result.deltas_calculated = #diffs
  result.min_delta = min_diff
  result.max_delta = max_diff
  result.avg_delta = format("%.2f", avg_diff)
  result.standard_deviation = format("%.2f", std_dev)
  result.variance = format("%.2f", variance)
  result.delta_range = s_range
  result.difficulty_level = difficulty_level
  result.sequence_grade = tcp_sequence_grade

  return result
end
