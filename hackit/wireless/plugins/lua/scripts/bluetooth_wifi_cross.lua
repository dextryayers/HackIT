local iface = arg[1]
local scan_type = arg[2] or "classic"

local bt_devices = {}
local wifi_aps = {}
local correlations = {}

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":' .. json_escape(iface) .. ',"bssid":"","ssid":"","channel":"","data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
  io.flush()
end

local function mac_normalize(mac)
  if not mac then return nil end
  local normalized = mac:upper():gsub("[^A-F0-9]", "")
  if #normalized ~= 12 then return nil end
  return normalized:sub(1, 2) .. ":" .. normalized:sub(3, 4) .. ":" ..
         normalized:sub(5, 6) .. ":" .. normalized:sub(7, 8) .. ":" ..
         normalized:sub(9, 10) .. ":" .. normalized:sub(11, 12)
end

local function oui_lookup(mac)
  local oui_prefix = mac:sub(1, 8):gsub(":", "")
  local oui_table = {
    ["00037F"] = "Intel",
    ["001CBE"] = "Intel",
    ["00E04C"] = "Realtek",
    ["00C0CA"] = "Broadcom",
    ["000EC6"] = "Broadcom",
    ["001583"] = "Broadcom",
    ["001A11"] = "Qualcomm",
    ["001D0F"] = "Qualcomm",
    ["002512"] = "Apple",
    ["003065"] = "Apple",
    ["001124"] = "Apple",
    ["0026B0"] = "Apple",
    ["000393"] = "Samsung",
    ["001E5E"] = "Samsung",
    ["001EE0"] = "Samsung",
    ["00A0C9"] = "Intel",
    ["001635"] = "Intel"
  }
  return oui_table[oui_prefix] or "Unknown"
end

local function scan_bluetooth_classic()
  telemetry("bt_scan", '{"type":"classic"}')
  local cmd = "hcitool scan --flush 2>/dev/null"
  local f = io.popen(cmd)
  if not f then
    telemetry("bt_error", '{"error":"hcitool not available"}')
    return {}
  end
  local devices = {}
  while true do
    local line = f:read("*l")
    if not line then break end
    local mac, name = line:match("(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)%s+(.+)")
    if mac then
      local normalized = mac_normalize(mac)
      if normalized then
        devices[normalized] = {
          name = name or "Unknown",
          mac = normalized,
          type = "classic",
          manufacturer = oui_lookup(normalized),
          first_seen = os.time()
        }
        telemetry("bt_device", '{"mac":' .. json_escape(normalized) .. ',"name":' .. json_escape(name or "Unknown") .. ',"type":"classic","manufacturer":' .. json_escape(oui_lookup(normalized)) .. '}')
      end
    end
  end
  f:close()
  return devices
end

local function scan_bluetooth_le()
  telemetry("bt_scan", '{"type":"LE"}')
  local cmd = "timeout 10 hcitool lescan --duplicate 2>/dev/null"
  local f = io.popen(cmd)
  if not f then
    telemetry("bt_error", '{"error":"hcitool lescan not available"}')
    return {}
  end
  local devices = {}
  while true do
    local line = f:read("*l")
    if not line then break end
    local mac, name = line:match("(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)%s+(.*)")
    if mac then
      local normalized = mac_normalize(mac)
      if normalized and not devices[normalized] then
        devices[normalized] = {
          name = name or "Unknown",
          mac = normalized,
          type = "LE",
          manufacturer = oui_lookup(normalized),
          first_seen = os.time()
        }
        telemetry("bt_device", '{"mac":' .. json_escape(normalized) .. ',"name":' .. json_escape(name or "Unknown") .. ',"type":"LE","manufacturer":' .. json_escape(oui_lookup(normalized)) .. '}')
      end
    end
  end
  f:close()
  return devices
end

local function scan_bluetoothctl()
  telemetry("bt_scan", '{"type":"bluetoothctl"}')
  os.execute("bluetoothctl --timeout 10 scan on 2>/dev/null &")
  os.execute("sleep 12")
  os.execute("bluetoothctl --timeout 5 scan off 2>/dev/null")
  local cmd = "bluetoothctl devices 2>/dev/null"
  local f = io.popen(cmd)
  if not f then return {} end
  local devices = {}
  while true do
    local line = f:read("*l")
    if not line then break end
    local mac, name = line:match("Device%s+([%x:]+)%s+(.*)")
    if mac then
      local normalized = mac_normalize(mac)
      if normalized and not devices[normalized] then
        devices[normalized] = {
          name = name or "Unknown",
          mac = normalized,
          type = "bluetoothctl",
          manufacturer = oui_lookup(normalized),
          first_seen = os.time()
        }
        telemetry("bt_device", '{"mac":' .. json_escape(normalized) .. ',"name":' .. json_escape(name or "Unknown") .. ',"type":"bluetoothctl","manufacturer":' .. json_escape(oui_lookup(normalized)) .. '}')
      end
    end
  end
  f:close()
  return devices
end

local function scan_wifi_aps()
  telemetry("wifi_scan", '{"iface":' .. json_escape(iface) .. '}')
  local cmd = "iw dev " .. iface .. " scan 2>/dev/null | grep -E \"BSS|SSID|freq|signal|Last beacon\""
  local f = io.popen(cmd)
  if not f then
    telemetry("wifi_error", '{"error":"iw scan failed"}')
    return {}
  end
  local aps = {}
  local current_bssid = nil
  local current_ap = nil

  while true do
    local line = f:read("*l")
    if not line then break end
    local bssid_match = line:match("BSS%s+([%x:]+)%s")
    if bssid_match then
      if current_ap and current_bssid then
        aps[current_bssid] = current_ap
      end
      current_bssid = mac_normalize(bssid_match)
      current_ap = {bssid = current_bssid, ssid = "", signal = -100, channel = 0, manufacturer = oui_lookup(current_bssid or "00:00:00:00:00:00")}
    end
    local ssid_match = line:match("SSID:%s*(.*)")
    if ssid_match and current_ap then
      current_ap.ssid = ssid_match
    end
    local signal_match = line:match("signal:%s*([-]?%d+)")
    if signal_match and current_ap then
      current_ap.signal = tonumber(signal_match)
    end
    local freq_match = line:match("freq:%s*(%d+)")
    if freq_match and current_ap then
      local freq = tonumber(freq_match)
      if freq then
        if freq >= 2400 and freq <= 2500 then
          current_ap.channel = (freq - 2407) / 5
          current_ap.band = "2.4GHz"
        elseif freq >= 5000 and freq <= 6000 then
          current_ap.channel = (freq - 5000) / 5
          current_ap.band = "5GHz"
        end
      end
    end
  end
  if current_ap and current_bssid then
    aps[current_bssid] = current_ap
  end
  f:close()
  return aps
end

local function correlate_devices()
  telemetry("correlation_start", '{"bt_devices":' .. tostring(#bt_devices) .. ',"wifi_aps":' .. tostring(#wifi_aps) .. '}')
  local oui_wifi = {}
  local oui_bt = {}

  for mac, ap in pairs(wifi_aps) do
    local prefix = mac:sub(1, 8)
    oui_wifi[prefix] = (oui_wifi[prefix] or 0) + 1
  end
  for mac, dev in pairs(bt_devices) do
    local prefix = mac:sub(1, 8)
    oui_bt[prefix] = (oui_bt[prefix] or 0) + 1
  end

  for mac, ap in pairs(wifi_aps) do
    local prefix = ap.bssid:sub(1, 8)
    if oui_bt[prefix] then
      local match = {
        type = "oui_match",
        bssid = ap.bssid,
        ssid = ap.ssid,
        manufacturer = ap.manufacturer,
        channel = ap.channel,
        band = ap.band,
        signal = ap.signal,
        bt_count = oui_bt[prefix]
      }
      correlations[#correlations + 1] = match
      telemetry("correlation", '{"type":"oui_match","bssid":' .. json_escape(ap.bssid) .. ',"ssid":' .. json_escape(ap.ssid) .. ',"manufacturer":' .. json_escape(ap.manufacturer) .. ',"bt_devices_with_same_oui":' .. tostring(oui_bt[prefix]) .. '}')
    end
  end

  for mac, dev in pairs(bt_devices) do
    local prefix = dev.mac:sub(1, 8)
    if oui_wifi[prefix] then
      telemetry("bt_wifi_co located", '{"bt_mac":' .. json_escape(dev.mac) .. ',"bt_name":' .. json_escape(dev.name) .. ',"manufacturer":' .. json_escape(dev.manufacturer) .. ',"wifi_aps_same_oui":' .. tostring(oui_wifi[prefix]) .. '}')
    end
  end
end

if not iface then
  telemetry("error", '{"error":"Usage: bluetooth_wifi_cross.lua <wifi_iface> [classic|LE|both|bluetoothctl]"}')
  os.exit(1)
end

local ok, err = pcall(function()
  telemetry("cross_scan_start", '{"scan_type":' .. json_escape(scan_type) .. '}')

  if scan_type == "classic" or scan_type == "both" then
    local classic = scan_bluetooth_classic()
    for k, v in pairs(classic) do bt_devices[k] = v end
  end
  if scan_type == "LE" or scan_type == "both" then
    local le = scan_bluetooth_le()
    for k, v in pairs(le) do bt_devices[k] = v end
  end
  if scan_type == "bluetoothctl" or scan_type == "both" then
    local bctl = scan_bluetoothctl()
    for k, v in pairs(bctl) do bt_devices[k] = v end
  end
  if scan_type == "both" then
    -- Default to all methods
    if #bt_devices == 0 then
      local classic = scan_bluetooth_classic()
      for k, v in pairs(classic) do bt_devices[k] = v end
      local le = scan_bluetooth_le()
      for k, v in pairs(le) do bt_devices[k] = v end
    end
  end

  local aps = scan_wifi_aps()
  for k, v in pairs(aps) do wifi_aps[k] = v end

  for _, ap in pairs(wifi_aps) do
    telemetry("wifi_ap", '{"bssid":' .. json_escape(ap.bssid) .. ',"ssid":' .. json_escape(ap.ssid) .. ',"signal":' .. tostring(ap.signal) .. ',"channel":' .. tostring(ap.channel) .. ',"band":' .. json_escape(ap.band or "unknown") .. ',"manufacturer":' .. json_escape(ap.manufacturer) .. '}')
  end

  correlate_devices()

  telemetry("summary", '{"bt_devices":' .. tostring(#bt_devices) .. ',"wifi_aps":' .. tostring(#wifi_aps) .. ',"correlations":' .. tostring(#correlations) .. '}')
end)
if not ok then
  telemetry("error", '{"error":"Cross scan failed: ' .. json_escape(tostring(err)) .. '"}')
end

telemetry("complete", '{"scan_type":' .. json_escape(scan_type) .. '}')
