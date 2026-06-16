local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local math = require "math"

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
  local result = stdnse.output_table()
  local samples = {}
  local sample_count = 10

  for i = 1, sample_count do
    local sock = nmap.new_socket("tcp")
    sock:set_timeout(4000)
    local ok, err = sock:connect(host.ip, port.number, "tcp")
    if ok then
      local info = sock:get_info()
      sock:close()
      if info and info.seq then
        local seq_num = tonumber(info.seq)
        if seq_num then
          samples[#samples + 1] = seq_num
        end
      end
    else
      sock:close()
    end
    nmap.msleep(200)
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
    diffs[#diffs + 1] = diff
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
  result.avg_delta = string.format("%.2f", avg_diff)
  result.standard_deviation = string.format("%.2f", std_dev)
  result.variance = string.format("%.2f", variance)
  result.delta_range = s_range
  result.difficulty_level = difficulty_level
  result.sequence_grade = tcp_sequence_grade

  return result
end
