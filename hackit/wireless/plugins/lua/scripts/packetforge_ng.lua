local output_file = arg[1] or "/tmp/crafted_packets.pcap"
local frame_type = arg[2] or "arp"
local src_mac = arg[3] or "AA:BB:CC:DD:EE:FF"
local dst_mac = arg[4] or "ff:ff:ff:ff:ff:ff"
local bssid = arg[5] or src_mac
local payload = arg[6] or ""

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":"","bssid":' .. json_escape(bssid) .. ',"ssid":"","channel":"","data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
  io.flush()
end

local frame_types = {
  arp = function()
    return "packetforge-ng -0 -a " .. bssid .. " -h " .. src_mac .. " -k " .. dst_mac .. " -l " .. bssid .. " -y /tmp/keystream.xor -w " .. output_file
  end,
  udp = function()
    local p = (payload and #payload > 0) and payload or "Hello from packetforge-ng"
    return "packetforge-ng -9 -a " .. bssid .. " -h " .. src_mac .. " -k " .. dst_mac .. " -l " .. bssid .. " -s 12345 -d 80 -p " .. p .. " -w " .. output_file
  end,
  icmp = function()
    return "packetforge-ng -1 -a " .. bssid .. " -h " .. src_mac .. " -k " .. dst_mac .. " -l " .. bssid .. " -w " .. output_file
  end,
  null = function()
    return "packetforge-ng -2 -a " .. bssid .. " -h " .. src_mac .. " -k " .. dst_mac .. " -l " .. bssid .. " -w " .. output_file
  end,
  auth = function()
    return "packetforge-ng -3 -a " .. bssid .. " -h " .. src_mac .. " -k " .. dst_mac .. " -w " .. output_file
  end,
  deauth = function()
    return "packetforge-ng -4 -a " .. bssid .. " -h " .. src_mac .. " -k " .. dst_mac .. " -w " .. output_file
  end
}

local function forge_packet(cmd)
  telemetry("forge_start", '{"type":' .. json_escape(frame_type) .. ',"cmd":' .. json_escape(cmd) .. ',"output":' .. json_escape(output_file) .. '}')
  local f = io.popen(cmd .. " 2>/dev/null", "r")
  if not f then
    telemetry("forge_fail", '{"error":"Failed to run packetforge-ng"}')
    return false
  end
  local out = f:read("*a")
  f:close()
  local size = 0
  local sf = io.open(output_file, "r")
  if sf then
    local contents = sf:read("*a")
    size = #contents
    sf:close()
  end
  telemetry("forge_result", '{"output_file":' .. json_escape(output_file) .. ',"size":' .. tostring(size) .. ',"output":' .. json_escape(out:sub(1, 200)) .. '}')
  return size > 0
end

local function verify_pcap()
  local f = io.popen("capinfos " .. output_file .. " 2>/dev/null", "r")
  if not f then
    telemetry("verify_fail", '{"error":"Cannot verify pcap"}')
    return
  end
  local out = f:read("*a")
  f:close()
  local packets = out:match("Number of packets:%s+(%d+)")
  telemetry("pcap_info", '{"packets":' .. json_escape(packets or "0") .. '}')
end

if not output_file or not frame_type then
  telemetry("error", '{"error":"Usage: packetforge_ng.lua <output_file> <frame_type> [src_mac] [dst_mac] [bssid] [payload]"}')
  os.exit(1)
end

local ok, err = pcall(function()
  local builder = frame_types[frame_type]
  if not builder then
    telemetry("error", '{"error":"Unknown frame type: ' .. frame_type .. '"}')
    os.exit(1)
  end
  local cmd = builder()
  if forge_packet(cmd) then
    verify_pcap()
  end
end)

if not ok then
  telemetry("error", '{"error":' .. json_escape(tostring(err)) .. '}')
  os.exit(1)
end

telemetry("complete", '{"output":' .. json_escape(output_file) .. ',"type":' .. json_escape(frame_type) .. '}')
