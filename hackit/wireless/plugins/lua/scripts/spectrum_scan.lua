local iface = arg[1]
local band = arg[2] or "2ghz"

local results = {}

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":' .. json_escape(iface) .. ',"bssid":"","ssid":"","channel":"","data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
  io.flush()
end

local function get_2ghz_channels()
  return {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
end

local function get_5ghz_channels()
  return {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165}
end

local function get_channels()
  if band == "5ghz" then
    return get_5ghz_channels()
  elseif band == "all" then
    local all = {}
    for _, v in ipairs(get_2ghz_channels()) do all[#all + 1] = v end
    for _, v in ipairs(get_5ghz_channels()) do all[#all + 1] = v end
    return all
  end
  return get_2ghz_channels()
end

local function survey_channel(ch)
  os.execute("iw dev " .. iface .. " set channel " .. ch .. " 2>/dev/null")
  os.execute("iw dev " .. iface .. " survey dump 2>/dev/null > /tmp/survey_" .. iface .. "_" .. ch .. ".txt")
  os.execute("sleep 0.3")

  local f = io.open("/tmp/survey_" .. iface .. "_" .. ch .. ".txt", "r")
  if not f then
    telemetry("survey_fail", '{"channel":' .. tostring(ch) .. '}')
    return nil
  end
  local data = f:read("*a")
  f:close()

  local noise = data:match("[Nn]oise%s*:?%s*(-?%d+)")
  local active_time = data:match("[Aa]ctive%s*[Tt]ime%s*:?%s*(%d+)")
  local busy_time = data:match("[Bb]usy%s*[Tt]ime%s*:?%s*(%d+)")
  local channel_time = data:match("[Cc]hannel%s*[Tt]ime%s*:?%s*(%d+)")
  local rx_time = data:match("RX%s*[Tt]ime%s*:?%s*(%d+)")
  local tx_time = data:match("TX%s*[Tt]ime%s*:?%s*(%d+)")

  local utilization = 0
  if channel_time and tonumber(channel_time) > 0 then
    local busy_val = tonumber(busy_time) or 0
    local chan_val = tonumber(channel_time)
    utilization = math.floor((busy_val / chan_val) * 100)
  end

  return {
    channel = ch,
    noise = tonumber(noise) or -95,
    active_ms = tonumber(active_time) or 0,
    busy_ms = tonumber(busy_time) or 0,
    total_ms = tonumber(channel_time) or 0,
    rx_ms = tonumber(rx_time) or 0,
    tx_ms = tonumber(tx_time) or 0,
    utilization = utilization
  }
end

local function scan_aps_on_channel(ch)
  local cmd = "airodump-ng " .. iface .. " -c " .. ch .. " --bssid 00:00:00:00:00:00 2>/dev/null &"
  os.execute(cmd)
  os.execute("sleep 0.5")
  os.execute("killall airodump-ng 2>/dev/null")
  local f = io.popen("iw dev " .. iface .. " station dump 2>/dev/null | wc -l")
  local client_count = 0
  if f then
    client_count = tonumber(f:read("*a")) or 0
    f:close()
  end
  return client_count
end

local function score_channel(data)
  local score = 100
  score = score - data.utilization
  if data.noise and data.noise > -80 then
    score = score - ((data.noise + 80) * 2)
  end
  if data.noise and data.noise < -95 then
    score = score + 10
  end
  return math.max(0, math.min(100, score))
end

local function scan_spectrum()
  local channels = get_channels()
  telemetry("scan_start", '{"band":' .. json_escape(band) .. ',"channels":' .. tostring(#channels) .. '}')

  for _, ch in ipairs(channels) do
    local ok, survey = pcall(survey_channel, ch)
    if ok and survey then
      local ap_count = 0
      local ok2, aps = pcall(scan_aps_on_channel, ch)
      if ok2 then ap_count = aps end

      survey.ap_count = ap_count
      survey.score = score_channel(survey)
      results[ch] = survey

      telemetry("channel_data", '{"channel":' .. tostring(ch) .. ',"noise":' .. tostring(survey.noise) .. ',"utilization":' .. tostring(survey.utilization) .. ',"ap_count":' .. tostring(ap_count) .. ',"score":' .. tostring(survey.score) .. '}')
    end
  end

  local best = {channel = 0, score = -1}
  local worst = {channel = 0, score = 999}
  for ch, data in pairs(results) do
    if data.score > best.score then
      best = {channel = ch, score = data.score, noise = data.noise, utilization = data.utilization, ap_count = data.ap_count}
    end
    if data.score < worst.score then
      worst = {channel = ch, score = data.score, noise = data.noise, utilization = data.utilization, ap_count = data.ap_count}
    end
  end

  local avg_noise, avg_util, avg_ap = 0, 0, 0
  local count = 0
  for _, data in pairs(results) do
    avg_noise = avg_noise + (data.noise or 0)
    avg_util = avg_util + (data.utilization or 0)
    avg_ap = avg_ap + (data.ap_count or 0)
    count = count + 1
  end
  if count > 0 then
    avg_noise = math.floor(avg_noise / count)
    avg_util = math.floor(avg_util / count)
    avg_ap = math.floor(avg_ap / count)
  end

  telemetry("best_channel", '{"channel":' .. tostring(best.channel) .. ',"score":' .. tostring(best.score) .. ',"noise":' .. tostring(best.noise) .. ',"utilization":' .. tostring(best.utilization) .. ',"ap_count":' .. tostring(best.ap_count) .. '}')
  telemetry("worst_channel", '{"channel":' .. tostring(worst.channel) .. ',"score":' .. tostring(worst.score) .. ',"noise":' .. tostring(worst.noise) .. ',"utilization":' .. tostring(worst.utilization) .. ',"ap_count":' .. tostring(worst.ap_count) .. '}')
  telemetry("averages", '{"band":' .. json_escape(band) .. ',"avg_noise":' .. tostring(avg_noise) .. ',"avg_utilization":' .. tostring(avg_util) .. ',"avg_ap":' .. tostring(avg_ap) .. ',"total_channels":' .. tostring(count) .. '}')
end

if not iface then
  telemetry("error", '{"error":"Usage: spectrum_scan.lua <iface> [2ghz|5ghz|all]"}')
  os.exit(1)
end

local ok, err = pcall(scan_spectrum)
if not ok then
  telemetry("error", '{"error":"Spectrum scan failed: ' .. json_escape(tostring(err)) .. '"}')
  telemetry("fallback", '{"message":"Trying iw scan fallback"}')
  local cmd = "iw dev " .. iface .. " scan 2>/dev/null | head -100"
  local f = io.popen(cmd)
  if f then
    local out = f:read("*a")
    f:close()
    telemetry("scan_result", '{"data":' .. json_escape(out:sub(1, 1000)) .. '}')
  end
end

telemetry("complete", '{"band":' .. json_escape(band) .. '}')
