#!/usr/bin/env lua

local iface = arg[1]
local bssid = arg[2] or ""
local channel = arg[3] or ""
local output_dir = arg[4] or "/tmp/handshakes"
local timeout = tonumber(arg[5]) or 60

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
  if out:find("type monitor") then
    telemetry("monitor_ok", '{"message":"Monitor mode confirmed"}')
    return true
  end
  telemetry("monitor_fail", '{"message":"Interface not in monitor mode"}')
  return false
end

local function ensure_dir()
  os.execute("mkdir -p " .. output_dir)
end

local function start_airodump()
  local filter = ""
  if bssid ~= "" then filter = " --bssid " .. bssid end
  if channel ~= "" then filter = filter .. " -c " .. channel end
  local cmd = "airodump-ng -w " .. output_dir .. "/capture" .. filter .. " " .. iface .. " 2>/dev/null &"
  telemetry("sniff_start", '{"cmd":' .. json_escape(cmd) .. ',"timeout":' .. tostring(timeout) .. ',"output":' .. json_escape(output_dir) .. '}')
  os.execute(cmd)
  telemetry("airodump_pid", '{"pid":"started"}')
end

local function check_for_handshakes()
  local cap_file = output_dir .. "/capture-01.cap"
  local csv_file = output_dir .. "/capture-01.csv"
  local found = false
  local elapsed = 0
  while elapsed < timeout do
    local f = io.open(csv_file, "r")
    if f then
      local content = f:read("*a")
      f:close()
      if content:find("WPA") or content:find("handshake") then
        telemetry("handshake_detected", '{"file":' .. json_escape(cap_file) .. '}')
        found = true
        break
      end
    end
    local cap_f = io.open(cap_file, "rb")
    if cap_f then
      local size = cap_f:seek("end")
      cap_f:close()
      if size and size > 500 then
        telemetry("capture_data", '{"file_size":' .. tostring(size) .. '}')
      end
    end
    os.execute("sleep 2")
    elapsed = elapsed + 2
    telemetry("sniff_progress", '{"elapsed":' .. tostring(elapsed) .. ',"timeout":' .. tostring(timeout) .. '}')
  end
  return found
end

local function parse_pmkid()
  local cap_file = output_dir .. "/capture-01.cap"
  local cmd = "tshark -r " .. cap_file .. " -Y 'eapol' -T fields -e wlan.sa -e wlan.da -e eapol.keydes.keyinfo 2>/dev/null"
  telemetry("pmkid_parse", '{"cmd":' .. json_escape(cmd) .. '}')
  local f = io.popen(cmd)
  if not f then
    telemetry("pmkid_fail", '{"error":"tshark not available"}')
    return
  end
  local count = 0
  while true do
    local line = f:read("*l")
    if not line then break end
    count = count + 1
    telemetry("eapol_frame", '{"frame":' .. tostring(count) .. ',"data":' .. json_escape(line:sub(1, 200)) .. '}')
  end
  f:close()
  if count > 0 then
    telemetry("pmkid_result", '{"eapol_frames":' .. tostring(count) .. '}')
  end
end

local function extract_with_tshark()
  local cap_file = output_dir .. "/capture-01.cap"
  local cmd = "tshark -r " .. cap_file .. " -Y 'eapol' -w " .. output_dir .. "/eapol_only.pcap 2>/dev/null"
  os.execute(cmd)
  local cmd2 = "tshark -r " .. output_dir .. "/eapol_only.pcap -T fields -e wlan.sa -e wlan.da -e eapol.keydes.key_info 2>/dev/null"
  local f = io.popen(cmd2)
  if not f then return end
  local lines = 0
  while true do
    local line = f:read("*l")
    if not line then break end
    lines = lines + 1
  end
  f:close()
  telemetry("tshark_result", '{"eapol_frames":' .. tostring(lines) .. ',"output":' .. json_escape(output_dir .. "/eapol_only.pcap") .. '}')
end

if arg[1] == "--help" then
  print("Usage: handshake_sniffer.lua <interface> [bssid] [channel] [output_dir] [timeout]")
  print("Captures WPA/WPA2 handshakes with PMKID extraction")
  print("Example: handshake_sniffer.lua wlan0 AA:BB:CC:DD:EE:FF 6 /tmp/hs 120")
  os.exit(0)
end

if not iface then
  telemetry("error", '{"error":"Usage: handshake_sniffer.lua <interface> [bssid] [channel] [output_dir] [timeout]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Monitor mode required on ' .. iface .. '"}')
  os.exit(1)
end

ensure_dir()
start_airodump()

local found = check_for_handshakes()
if found then
  telemetry("handshake_success", '{"message":"Handshake captured successfully"}')
else
  telemetry("handshake_timeout", '{"message":"No handshake captured within timeout"}')
end

os.execute("pkill -f 'airodump-ng.*" .. iface .. "' 2>/dev/null")
os.execute("sleep 1")
parse_pmkid()
extract_with_tshark()

telemetry("complete", '{"found":' .. tostring(found) .. ',"output_dir":' .. json_escape(output_dir) .. '}')
