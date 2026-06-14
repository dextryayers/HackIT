local iface = arg[1]
local duration = tonumber(arg[2]) or 60

local stats = {
  deauth_total = 0,
  disassoc_total = 0,
  sources = {},
  rates = {},
  start_time = os.time()
}

local alert_threshold = 20
local window_size = 10

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":' .. json_escape(iface) .. ',"bssid":"","ssid":"","channel":"","data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
  io.flush()
end

local function check_monitor_mode()
  local cmd = "iw dev " .. iface .. " info 2>/dev/null"
  local f = io.popen(cmd)
  if not f then return false end
  local out = f:read("*a")
  f:close()
  return out:find("type monitor") ~= nil
end

local function mac_to_str(raw_mac)
  if #raw_mac < 6 then return "00:00:00:00:00:00" end
  return string.format("%02x:%02x:%02x:%02x:%02x:%02x",
    string.byte(raw_mac, 1), string.byte(raw_mac, 2), string.byte(raw_mac, 3),
    string.byte(raw_mac, 4), string.byte(raw_mac, 5), string.byte(raw_mac, 6))
end

local function parse_deauth_frame(payload)
  if #payload < 26 then return nil end
  local fc = string.byte(payload, 1)
  local subtype = (fc >> 4) & 0x0f
  local frame_type = fc & 0x0c

  -- Management frame
  if frame_type ~= 0 then return nil end

  local is_deauth = (subtype == 12)
  local is_disassoc = (subtype == 10)

  if not is_deauth and not is_disassoc then return nil end

  local da = mac_to_str(payload:sub(5, 10))
  local sa = mac_to_str(payload:sub(11, 16))
  local bssid = mac_to_str(payload:sub(17, 22))
  local reason_offset = 25
  local reason_code = 0
  if #payload >= reason_offset + 2 then
    reason_code = string.byte(payload, reason_offset) + string.byte(payload, reason_offset + 1) * 256
  end

  return {
    da = da,
    sa = sa,
    bssid = bssid,
    reason = reason_code,
    is_deauth = is_deauth,
    is_disassoc = is_disassoc,
    timestamp = os.time()
  }
end

local function detect_attack_pattern(source_mac, current_rate)
  local patterns = {}
  if current_rate > 50 then
    patterns[#patterns + 1] = "aireplay-ng_style"
  end
  if current_rate > 100 then
    patterns[#patterns + 1] = "mdk4_style"
  end
  if current_rate > 200 then
    patterns[#patterns + 1] = "mdk3_style"
  end
  if stats.sources[source_mac] and stats.sources[source_mac] > 50 then
    patterns[#patterns + 1] = "persistent_attack"
  end
  return patterns
end

local function monitor_traffic()
  telemetry("monitor_start", '{"iface":' .. json_escape(iface) .. ',"duration":' .. tostring(duration) .. '}')

  local cmd = "tcpdump -l -i " .. iface .. " -s 128 -y IEEE802_11_RADIO type mgt and (subtype deauth or subtype disassoc) 2>/dev/null"
  local f = io.popen(cmd)
  if not f then
    local cmd2 = "tshark -l -i " .. iface .. " -Y \"wlan.fc.type_subtype == 10 || wlan.fc.type_subtype == 12\" -T fields -e frame.time_epoch -e wlan.sa -e wlan.da -e wlan.bssid -e wlan.deauth_reason 2>/dev/null"
    f = io.popen(cmd2)
    if not f then
      telemetry("error", '{"error":"tcpdump and tshark unavailable, trying airodump-ng"}')
      local cmd3 = "airodump-ng " .. iface .. " 2>/dev/null"
      f = io.popen(cmd3)
      if not f then
        telemetry("error", '{"error":"No capture tool available"}')
        return nil
      end
      telemetry("capture_mode", '{"method":"airodump"}')
      return f, "airodump"
    end
    telemetry("capture_mode", '{"method":"tshark"}')
    return f, "tshark"
  end
  telemetry("capture_mode", '{"method":"tcpdump"}')
  return f, "tcpdump"
end

local function analyze_traffic(sniffer, method)
  local end_time = os.time() + duration
  local window_frames = {}
  local alert_sent = {}

  while os.time() < end_time do
    local line = sniffer:read("*l")
    if not line then break end

    local source_mac = nil
    local is_deauth = false
    local is_disassoc = false
    local reason = nil

    if method == "tshark" then
      local parts = {}
      for val in line:gmatch("%S+") do
        parts[#parts + 1] = val
      end
      if #parts >= 4 then
        source_mac = parts[2]
        if #parts >= 5 then
          reason = parts[5]
        end
      end
      is_deauth = true
    elseif method == "tcpdump" then
      if line:find("Deauth") or line:find("deauth") then
        is_deauth = true
      elseif line:find("Disassoc") or line:find("disassoc") then
        is_disassoc = true
      end
      source_mac = line:match("SA:([%x:]+)")
      if not source_mac then
        source_mac = line:match("([%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x])")
      end
    else
      if line:find("Deauth") or line:find("deauth") then is_deauth = true end
      if line:find("Disassoc") or line:find("disassoc") then is_disassoc = true end
      source_mac = line:match("([%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x])")
    end

    if not source_mac then
      telemetry("parse_skip", '{"raw":' .. json_escape(line:sub(1, 100)) .. '}')
    end

    if source_mac then
      if is_deauth then
        stats.deauth_total = stats.deauth_total + 1
        stats.sources[source_mac] = (stats.sources[source_mac] or 0) + 1
      end
      if is_disassoc then
        stats.disassoc_total = stats.disassoc_total + 1
        stats.sources[source_mac] = (stats.sources[source_mac] or 0) + 1
      end

      local now = os.time()
      window_frames[#window_frames + 1] = now
      while #window_frames > 0 and window_frames[1] < now - window_size do
        table.remove(window_frames, 1)
      end

      local current_rate = #window_frames / window_size
      stats.rates[source_mac] = current_rate

      local event_type = "deauth"
      if is_disassoc then event_type = "disassoc" end

      telemetry(event_type, '{"source":' .. json_escape(source_mac) .. ',"reason":' .. json_escape(tostring(reason or "unknown")) .. ',"rate":' .. string.format("%.1f", current_rate) .. ',"total":' .. tostring(stats.deauth_total + stats.disassoc_total) .. '}')

      if current_rate > alert_threshold and not alert_sent[source_mac] then
        local patterns = detect_attack_pattern(source_mac, current_rate)
        telemetry("attack_alert", '{"source":' .. json_escape(source_mac) .. ',"rate":' .. string.format("%.1f", current_rate) .. ',"threshold":' .. tostring(alert_threshold) .. ',"detected_patterns":' .. json_escape(table.concat(patterns, ",")) .. ',"recommended_action":"Block source or channel hop"}')
        if current_rate > alert_threshold * 2 then
          alert_sent[source_mac] = true
        end
      end
    end
  end
  sniffer:close()
end

if not iface then
  telemetry("error", '{"error":"Usage: deauth_detect.lua <iface> [duration_seconds]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Interface not in monitor mode"}')
  os.exit(1)
end

local sniffer, method = monitor_traffic()
if sniffer then
  local ok, err = pcall(analyze_traffic, sniffer, method)
  if not ok then
    telemetry("error", '{"error":"Analysis error: ' .. json_escape(tostring(err)) .. '"}')
  end
end

telemetry("summary", '{"total_deauth":' .. tostring(stats.deauth_total) .. ',"total_disassoc":' .. tostring(stats.disassoc_total) .. ',"unique_sources":' .. tostring(#stats.sources) .. ',"duration":' .. tostring(duration) .. '}')
for src, count in pairs(stats.sources) do
  if count > 10 then
    telemetry("source", '{"mac":' .. json_escape(src) .. ',"count":' .. tostring(count) .. ',"rate":' .. string.format("%.1f", stats.rates[src] or 0) .. ',"suspicious":true}')
  end
end
telemetry("complete", '{"duration":' .. tostring(duration) .. '}')
