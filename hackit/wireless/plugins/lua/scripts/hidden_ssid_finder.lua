local iface = arg[1]
local channel = arg[2] or "1"
local timeout = tonumber(arg[3]) or 30

local found_networks = {}
local common_ssids = {"FreeWiFi", "WiFi", "guest", "Guest", "ATT", "xfinitywifi", "Starbucks", "McDonalds", "Home", "Office", "linksys", "netgear", "dlink", "TP-LINK", "eduroam", "airport", "default"}

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":' .. json_escape(iface) .. ',"bssid":"","ssid":"","channel":' .. json_escape(channel) .. ',"data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
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

local function set_channel(ch)
  os.execute("iw dev " .. iface .. " set channel " .. ch .. " 2>/dev/null")
  os.execute("iwconfig " .. iface .. " channel " .. ch .. " 2>/dev/null")
end

local function send_null_probe()
  local bssid = "AA:BB:CC:DD:EE:FF"
  local frame = string.char(0x40, 0x00, 0x00, 0x00)
  frame = frame .. string.char(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
  for b in bssid:gmatch("(%x%x)") do frame = frame .. string.char(tonumber(b, 16)) end
  for b in bssid:gmatch("(%x%x)") do frame = frame .. string.char(tonumber(b, 16)) end
  frame = frame .. string.char(0x00, 0x00)
  frame = frame .. string.char(0x00, 0x00)
  return frame
end

local function send_ssid_probe(ssid)
  local bssid = "AA:BB:CC:DD:EE:FF"
  local ssid_len = #ssid
  if ssid_len > 32 then ssid_len = 32 end
  local frame = string.char(0x40, 0x00, 0x00, 0x00)
  frame = frame .. string.char(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
  for b in bssid:gmatch("(%x%x)") do frame = frame .. string.char(tonumber(b, 16)) end
  for b in bssid:gmatch("(%x%x)") do frame = frame .. string.char(tonumber(b, 16)) end
  frame = frame .. string.char(0x00, 0x00)
  frame = frame .. string.char(0x00, ssid_len) .. ssid:sub(1, ssid_len)
  return frame
end

local function inject_probe(frame)
  local tmp = "/tmp/hidden_probe_" .. iface .. ".bin"
  local f = io.open(tmp, "wb")
  if not f then return end
  f:write(frame)
  f:close()
  os.execute("cat " .. tmp .. " | aireplay-ng -D " .. iface .. " 2>/dev/null")
end

local function parse_probe_response_bssid(line)
  local bssid_val = line:match("BSSID:?%s*([%x:]+)")
  if not bssid_val then
    bssid_val = line:match("([%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x])")
  end
  return bssid_val
end

local function parse_ssid_from_frame(payload)
  local ssid_seen = {}
  for i = 1, #payload - 2 do
    local tag = string.byte(payload, i)
    local len = string.byte(payload, i + 1)
    if tag == 0 and len > 0 and len <= 32 then
      local s = payload:sub(i + 2, i + 1 + len)
      if #s > 0 and not ssid_seen[s] then
        ssid_seen[s] = true
        return s
      end
    end
    if len > 0 then
      i = i + 1 + len
    end
  end
  return nil
end

local function sniff_probe_responses()
  local cmd = "tshark -l -i " .. iface .. " -Y \"wlan.fc.type_subtype == 5\" -T fields -e wlan.sa -e wlan.ssid -e radiotap.dbm_antsignal 2>/dev/null"
  local f = io.popen(cmd)
  if not f then
    telemetry("error", '{"error":"tshark not available, trying tcpdump"}')
    local cmd2 = "tcpdump -l -i " .. iface .. " -e -s 256 type mgt subtype probe-resp 2>/dev/null"
    f = io.popen(cmd2)
    if not f then
      telemetry("error", '{"error":"tcpdump not available either, trying airodump-ng"}')
      local cmd3 = "airodump-ng " .. iface .. " -c " .. channel .. " 2>/dev/null"
      f = io.popen(cmd3)
      if not f then
        telemetry("error", '{"error":"No sniffer available"}')
        return nil
      end
      telemetry("sniff_mode", '{"method":"airodump"}')
      return f, "airodump"
    end
    telemetry("sniff_mode", '{"method":"tcpdump"}')
    return f, "tcpdump"
  end
  telemetry("sniff_mode", '{"method":"tshark"}')
  return f, "tshark"
end

local function find_hidden_ssids()
  telemetry("scan_start", '{"channel":' .. json_escape(channel) .. ',"timeout":' .. tostring(timeout) .. '}')
  set_channel(channel)

  -- Send null probe requests
  local null_probe = send_null_probe()
  inject_probe(null_probe)
  telemetry("null_probe", '{"sent":true}')

  -- Send probes for common SSIDs
  for _, ssid in ipairs(common_ssids) do
    local probe = send_ssid_probe(ssid)
    inject_probe(probe)
    telemetry("ssid_probe", '{"ssid":' .. json_escape(ssid) .. '}')
  end

  local sniffer, method = sniff_probe_responses()
  if not sniffer then return end

  local start_time = os.time()
  local found_count = 0

  while os.time() - start_time < timeout do
    local line = sniffer:read("*l")
    if not line then break end

    local bssid_val = parse_probe_response_bssid(line)
    local ssid_val = line:match("%s+(%S+)%s*$")

    if method == "tcpdump" then
      if line:find("Probe Response") or line:find("probe-resp") then
        telemetry("probe_resp_raw", '{"line":' .. json_escape(line:sub(1, 200)) .. '}')
      end
    end

    if bssid_val and ssid_val and #ssid_val > 0 then
      if not found_networks[bssid_val] then
        found_networks[bssid_val] = ssid_val
        found_count = found_count + 1
        telemetry("hidden_ssid_found", '{"bssid":' .. json_escape(bssid_val) .. ',"ssid":' .. json_escape(ssid_val) .. ',"method":"probe_response"}')
      end
    end
  end
  sniffer:close()

  if found_count == 0 then
    telemetry("result", '{"message":"No hidden SSIDs found via probing","common_ssids_tried":' .. tostring(#common_ssids) .. '}')
  end
end

if not iface then
  telemetry("error", '{"error":"Usage: hidden_ssid_finder.lua <iface> [channel] [timeout]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Interface not in monitor mode"}')
  os.exit(1)
end

local ok, err = pcall(find_hidden_ssids)
if not ok then
  telemetry("error", '{"error":"Scan failed: ' .. json_escape(tostring(err)) .. '"}')
end

telemetry("complete", '{"found":' .. tostring(#found_networks) .. '}')
for bssid_val, ssid_val in pairs(found_networks) do
  telemetry("network", '{"bssid":' .. json_escape(bssid_val) .. ',"ssid":' .. json_escape(ssid_val) .. '}')
end
