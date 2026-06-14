local iface = arg[1]
local bssid = arg[2] or ""
local duration = tonumber(arg[3]) or 30

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":' .. json_escape(iface) .. ',"bssid":' .. json_escape(bssid) .. ',"ssid":"","channel":"","data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
  io.flush()
end

local function check_monitor_mode()
  local f = io.popen("iw dev " .. iface .. " info 2>/dev/null")
  if not f then return false end
  local out = f:read("*a")
  f:close()
  return out:find("type monitor") ~= nil
end

local function get_signal_station()
  local f = io.popen("iw dev " .. iface .. " station dump 2>/dev/null", "r")
  if not f then return nil end
  local out = f:read("*a")
  f:close()
  local signals = {}
  local current_mac = nil
  for line in out:gmatch("[^\n]+") do
    local mac = line:match("^Station%s+([%x:]+)")
    if mac then
      current_mac = mac
      if not signals[current_mac] then signals[current_mac] = {} end
    end
    local sig = line:match("signal:%s+([%-%d]+)")
    if sig and current_mac then
      table.insert(signals[current_mac], tonumber(sig))
    end
    local avg = line:match("signal avg:%s+([%-%d]+)")
    if avg and current_mac then
      if not signals[current_mac].avg then signals[current_mac].avg = {} end
      table.insert(signals[current_mac].avg, tonumber(avg))
    end
  end
  return signals
end

local function get_signal_scan()
  if not bssid or #bssid == 0 then return nil end
  local f = io.popen("iw dev " .. iface .. " scan 2>/dev/null", "r")
  if not f then return nil end
  local out = f:read("*a")
  f:close()
  local sig = out:match("BSS " .. bssid:gsub(":", "%%:") .. ".-signal: ([%-%d]+)")
  if sig then return {{bssid, tonumber(sig)}} end
  return nil
end

local function get_signal_tshark()
  local filter = "wlan.fc.type_subtype == 8"
  if bssid and #bssid > 0 then filter = filter .. " and wlan.sa == " .. bssid end
  local cmd = "tshark -i " .. iface .. " -Y '" .. filter .. "' -T fields -e wlan.sa -e radiotap.dbm_antsignal 2>/dev/null"
  local f = io.popen(cmd, "r")
  if not f then return nil end
  local signals = {}
  for i = 1, 10 do
    local line = f:read("*l")
    if not line then break end
    local mac, sig = line:match("([%x:]+)%s+([%-%d]+)")
    if mac and sig then
      if not signals[mac] then signals[mac] = {} end
      table.insert(signals[mac], tonumber(sig))
    end
  end
  f:close()
  return signals
end

local function monitor_signal()
  telemetry("monitor_start", '{"duration":' .. tostring(duration) .. '}')
  local all_readings = {}
  local start = os.time()
  local samples = 0
  while os.time() - start < duration do
    os.execute("sleep 1")
    local signals = get_signal_station()
    if not signals or next(signals) == nil then
      signals = get_signal_scan()
    end
    if not signals or next(signals) == nil then
      signals = get_signal_tshark()
    end
    if signals then
      for mac, sigs in pairs(signals) do
        if type(sigs) == "table" then
          for _, sig in ipairs(sigs) do
            if type(sig) == "number" then
              samples = samples + 1
              if not all_readings[mac] then all_readings[mac] = {} end
              table.insert(all_readings[mac], sig)
              telemetry("signal_sample", '{"mac":' .. json_escape(mac) .. ',"signal":' .. tostring(sig) .. '}')
            end
          end
        end
      end
    end
    telemetry("monitor_progress", '{"elapsed":' .. tostring(os.time() - start) .. ',"samples":' .. tostring(samples) .. '}')
  end
  for mac, readings in pairs(all_readings) do
    local min, max, total = readings[1], readings[1], 0
    for _, r in ipairs(readings) do
      if r < min then min = r end
      if r > max then max = r end
      total = total + r
    end
    local avg = total / #readings
    local variance = 0
    for _, r in ipairs(readings) do
      variance = variance + (r - avg) ^ 2
    end
    variance = variance / #readings
    local stdev = math.sqrt(variance)
    telemetry("signal_report", '{"mac":' .. json_escape(mac) .. ',"min":' .. tostring(min) .. ',"max":' .. tostring(max) .. ',"avg":' .. tostring(avg) .. ',"stdev":' .. tostring(stdev) .. ',"samples":' .. tostring(#readings) .. '}')
  end
end

if not iface then
  telemetry("error", '{"error":"Usage: signal_monitor.lua <interface> [bssid] [duration]"}')
  os.exit(1)
end

local ok, err = pcall(function()
  monitor_signal()
end)

if not ok then
  telemetry("error", '{"error":' .. json_escape(tostring(err)) .. '}')
  os.exit(1)
end

telemetry("complete", '{"duration":' .. tostring(duration) .. '}')
