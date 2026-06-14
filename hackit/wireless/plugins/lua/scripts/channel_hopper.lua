local iface = arg[1]
local band = arg[2] or "both"
local dwell_ms = tonumber(arg[3]) or 500
local channels_str = arg[4] or ""

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":' .. json_escape(iface) .. ',"bssid":"","ssid":"","channel":"","data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
  io.flush()
end

local function check_monitor_mode()
  local f = io.popen("iw dev " .. iface .. " info 2>/dev/null")
  if not f then return false end
  local out = f:read("*a")
  f:close()
  return out:find("type monitor") ~= nil
end

local channels_2ghz = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
local channels_5ghz = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165}

local function get_channels()
  if channels_str and #channels_str > 0 then
    local chs = {}
    for c in channels_str:gmatch("([%d]+)") do
      table.insert(chs, tonumber(c))
    end
    if #chs > 0 then return chs end
  end
  if band == "2.4" then return channels_2ghz end
  if band == "5" then return channels_5ghz end
  local all = {}
  for _, c in ipairs(channels_2ghz) do table.insert(all, c) end
  for _, c in ipairs(channels_5ghz) do table.insert(all, c) end
  return all
end

local function scan_on_channel(ch)
  os.execute("iw dev " .. iface .. " set channel " .. ch .. " 2>/dev/null")
  os.execute("sleep " .. (dwell_ms / 1000))
  local f = io.popen("iw dev " .. iface .. " scan 2>/dev/null", "r")
  if not f then return 0 end
  local out = f:read("*a")
  f:close()
  local count = 0
  local aps = {}
  for bssid, freq, signal, ssid in out:gmatch("BSS ([%x:]+).-freq: (%d+).-signal: ([%-%d]+).-SSID: ([^\n]+)") do
    count = count + 1
    local ch = math.floor((tonumber(freq) - 2412) / 5) + 1
    if tonumber(freq) > 5000 then
      local freqs = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165}
      local freq5 = {5180, 5200, 5220, 5240, 5260, 5280, 5300, 5320, 5500, 5520, 5540, 5560, 5580, 5600, 5620, 5640, 5660, 5680, 5700, 5745, 5765, 5785, 5805, 5825}
      for i, fq in ipairs(freq5) do
        if tonumber(freq) == fq then ch = freqs[i] break end
      end
    end
    table.insert(aps, {bssid = bssid, channel = ch, signal = signal, ssid = ssid})
  end
  for _, ap in ipairs(aps) do
    telemetry("ap_on_channel", '{"bssid":' .. json_escape(ap.bssid) .. ',"channel":' .. tostring(ch) .. ',"signal":' .. json_escape(ap.signal) .. ',"ssid":' .. json_escape(ap.ssid) .. '}')
  end
  telemetry("channel_result", '{"channel":' .. tostring(ch) .. ',"aps":' .. tostring(count) .. '}')
  return count
end

local function hop_channels()
  local channels = get_channels()
  telemetry("hopper_start", '{"channels":' .. tostring(#channels) .. ',"dwell_ms":' .. tostring(dwell_ms) .. ',"band":' .. json_escape(band) .. '}')
  local total_aps = 0
  local scan_count = 0
  while scan_count < 3 do
    scan_count = scan_count + 1
    for _, ch in ipairs(channels) do
      local aps = scan_on_channel(ch)
      total_aps = total_aps + aps
    end
    telemetry("scan_cycle", '{"cycle":' .. tostring(scan_count) .. ',"total_aps":' .. tostring(total_aps) .. '}')
    if total_aps > 0 then break end
  end
  telemetry("hopper_stop", '{"total_aps":' .. tostring(total_aps) .. ',"cycles":' .. tostring(scan_count) .. '}')
end

if not iface then
  telemetry("error", '{"error":"Usage: channel_hopper.lua <interface> [band] [dwell_ms] [channels]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Monitor mode required on ' .. iface .. '"}')
  os.exit(1)
end

local ok, err = pcall(function()
  hop_channels()
end)

if not ok then
  telemetry("error", '{"error":' .. json_escape(tostring(err)) .. '}')
  os.exit(1)
end

telemetry("complete", '{"band":' .. json_escape(band) .. '}')
