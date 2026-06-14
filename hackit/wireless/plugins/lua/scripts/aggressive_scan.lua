#!/usr/bin/env lua

local iface = arg[1] or "wlan0"
local channel_arg = arg[2]
local timeout = tonumber(arg[3]) or 10

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
  if out:find("type monitor") then
    telemetry("monitor_ok", '{"message":"Monitor mode confirmed"}')
    return true
  end
  telemetry("monitor_fail", '{"message":"Interface not in monitor mode"}')
  return false
end

local function scan_iw()
  local cmd = "iw dev " .. iface .. " scan 2>/dev/null"
  if channel_arg then
    cmd = "iw dev " .. iface .. " set channel " .. channel_arg .. " 2>/dev/null; " .. cmd
  end
  telemetry("scan_start", '{"method":"iw","timeout":' .. tostring(timeout) .. '}')
  local f = io.popen(cmd .. " 2>/dev/null &")
  if not f then return false end
  local out = f:read("*a")
  f:close()
  local raw = false
  local ap_count = 0
  local ssid = ""
  local bssid = ""
  local channel = ""
  local signal = ""
  local security = ""
  local band = ""
  for line in out:gmatch("[^\n]+") do
    local b = line:match("^BSS ([0-9a-fA-F:]+)")
    if b then
      if bssid ~= "" then
        local hidden = ""
        if ssid == "" or ssid:find("%s") then hidden = "true" end
        telemetry("ap_found", '{"ssid":' .. json_escape(ssid) .. ',"bssid":' .. json_escape(bssid) .. ',"channel":' .. json_escape(channel) .. ',"signal":' .. json_escape(signal) .. ',"security":' .. json_escape(security) .. ',"band":' .. json_escape(band) .. ',"hidden":' .. json_escape(hidden) .. '}')
        ap_count = ap_count + 1
      end
      bssid = b
      ssid = ""
      channel = ""
      signal = ""
      security = ""
      band = ""
    end
    local s = line:match("%s+SSID: (.+)")
    if s then ssid = s end
    local f = line:match("%s+freq: (%d+)")
    if f then
      local freq = tonumber(f)
      if freq and freq < 3000 then band = "2.4GHz" elseif freq and freq < 6000 then band = "5GHz" elseif freq then band = "6GHz" end
    end
    local ch = line:match("%s+channel: (%d+)")
    if ch then channel = ch end
    local sig = line:match("signal: (-?%d+%.?%d*)")
    if sig then signal = sig end
    local auth = line:match("Authentication suites: (.+)")
    if auth then
      if auth:find("802.1X") then security = "WPA-Enterprise"
      elseif auth:find("PSK") then security = "WPA2-PSK"
      else security = "Open" end
    end
    local rsn = line:match("RSN:")
    if rsn then
      security = "WPA2"
    end
    local wpa = line:match("WPA:")
    if wpa then
      if security == "WPA2" then security = "WPA2"
      else security = "WPA" end
    end
  end
  if bssid ~= "" then
    local hidden = ""
    if ssid == "" or ssid:find("%s") then hidden = "true" end
    telemetry("ap_found", '{"ssid":' .. json_escape(ssid) .. ',"bssid":' .. json_escape(bssid) .. ',"channel":' .. json_escape(channel) .. ',"signal":' .. json_escape(signal) .. ',"security":' .. json_escape(security) .. ',"band":' .. json_escape(band) .. ',"hidden":' .. json_escape(hidden) .. '}')
    ap_count = ap_count + 1
  end
  telemetry("scan_complete", '{"method":"iw","ap_count":' .. tostring(ap_count) .. '}')
  return ap_count > 0
end

local function scan_nmcli()
  local cmd = "nmcli -t -f SSID,BSSID,CHAN,SIGNAL,SECURITY,BAND dev wifi list ifname " .. iface .. " 2>/dev/null"
  telemetry("scan_start", '{"method":"nmcli"}')
  local f = io.popen(cmd)
  if not f then return false end
  local ap_count = 0
  while true do
    local line = f:read("*l")
    if not line then break end
    local parts = {}
    for p in line:gmatch("[^:]+") do
      table.insert(parts, p)
    end
    if #parts >= 5 then
      local ssid = parts[1]
      local bssid = parts[2] or ""
      local channel = parts[3] or ""
      local signal = parts[4] or ""
      local security = parts[5] or ""
      local band = parts[6] or ""
      local hidden = (ssid == "--" or ssid == "") and "true" or "false"
      telemetry("ap_found", '{"ssid":' .. json_escape(ssid) .. ',"bssid":' .. json_escape(bssid) .. ',"channel":' .. json_escape(channel) .. ',"signal":' .. json_escape(signal) .. ',"security":' .. json_escape(security) .. ',"band":' .. json_escape(band) .. ',"hidden":' .. json_escape(hidden) .. '}')
      ap_count = ap_count + 1
    end
  end
  f:close()
  telemetry("scan_complete", '{"method":"nmcli","ap_count":' .. tostring(ap_count) .. '}')
  return ap_count > 0
end

if arg[1] == "--help" then
  print("Usage: aggressive_scan.lua <interface> [channel] [timeout]")
  print("Scans for WiFi networks with hidden SSID detection")
  print("Example: aggressive_scan.lua wlan0 6 15")
  os.exit(0)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Monitor mode required on ' .. iface .. '"}')
end

local ok = scan_iw()
if not ok then
  telemetry("fallback", '{"message":"iw scan failed, trying nmcli"}')
  ok = scan_nmcli()
end
if not ok then
  telemetry("scan_fail", '{"error":"All scan methods failed"}')
end

telemetry("done", '{"method":ok and "success" or "failed"}')
