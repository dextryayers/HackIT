local pcap_file = arg[1]

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":"","bssid":"","ssid":"","channel":"","data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
  io.flush()
end

local handshake_steps = {[1] = 0, [2] = 0, [3] = 0, [4] = 0}
local anonce = nil
local snonce = nil
local mic_value = nil
local replay_counter = nil
local key_descriptors = {}

local function hex_bytes(s)
  if not s then return "" end
  local out = {}
  for i = 1, #s do
    out[#out + 1] = string.format("%02x", string.byte(s, i))
  end
  return table.concat(out, ":")
end

local function parse_eapol_key(data)
  if #data < 95 then return nil end
  local desc = {}
  desc.descriptor_type = string.byte(data, 1)
  if desc.descriptor_type ~= 2 then return nil end
  desc.key_info = string.byte(data, 2) + string.byte(data, 3) * 256
  desc.key_length = string.byte(data, 4) + string.byte(data, 5) * 256
  desc.replay_counter = string.byte(data, 6) + string.byte(data, 7) * 256 + string.byte(data, 8) * 65536 + string.byte(data, 9) * 16777216
  desc.nonce = data:sub(14, 45)
  desc.iv = data:sub(47, 62)
  desc.rsc = data:sub(63, 70)
  desc.key_id = data:sub(71, 72)
  desc.mic = data:sub(73, 88)
  desc.data_len = string.byte(data, 89) + string.byte(data, 90) * 256
  desc.key_data = data:sub(91, 91 + desc.data_len - 1)
  return desc
end

local function detect_handshake_step(eapol)
  local ki = eapol.key_info
  local install = (ki & 0x0040) ~= 0
  local ack = (ki & 0x0080) ~= 0
  local mic = (ki & 0x0100) ~= 0
  local secure = (ki & 0x0200) ~= 0
  local error_val = (ki & 0x0400) ~= 0
  local request = (ki & 0x0800) ~= 0

  local step = nil
  if ack and not mic and not install and not secure then
    step = 1
  elseif not ack and mic and not install and not secure then
    step = 2
  elseif ack and mic and install and not secure then
    step = 3
  elseif not ack and mic and not install and secure then
    step = 4
  end
  return step, ki
end

local function analyze_pcap()
  local cmd = "tshark -r " .. pcap_file .. " -Y \"eapol\" -T fields -e frame.number -e frame.time_epoch -e wlan.sa -e wlan.da -e eapol.keydes.keyinfo -e eapol.keydes.nonce -e eapol.keydes.mic -e eapol.keydes.replay_counter -e eapol.keydes.keydata 2>/dev/null"
  local f = io.popen(cmd)
  if not f then
    local cmd2 = "tcpdump -r " .. pcap_file .. " -xx -l -s 256 2>/dev/null | head -500"
    f = io.popen(cmd2)
    if not f then
      telemetry("error", '{"error":"Cannot read pcap file. Install tshark or tcpdump."}')
      return
    end
    telemetry("parse_mode", '{"method":"tcpdump_raw"}')
    local raw = f:read("*a")
    f:close()
    if #raw == 0 then
      telemetry("error", '{"error":"No data in pcap file"}')
      return
    end
    telemetry("raw_data", '{"length":' .. tostring(#raw) .. '}')
    return
  end

  telemetry("parse_mode", '{"method":"tshark"}')
  local frame_count = 0
  local total_eapol = 0

  while true do
    local line = f:read("*l")
    if not line then break end
    local parts = {}
    for val in line:gmatch("%S+") do
      parts[#parts + 1] = val
    end
    if #parts < 4 then
      telemetry("skip", '{"line":' .. json_escape(line:sub(1, 100)) .. '}')
    end
    total_eapol = total_eapol + 1
    local frame_num = parts[1] or "?"
    local timestamp = parts[2] or "0"
    local sa = parts[3] or "00:00:00:00:00:00"
    local da = parts[4] or "00:00:00:00:00:00"
    local keyinfo_hex = parts[5] or "0000"
    local nonce_hex = parts[6] or ""
    local mic_hex = parts[7] or ""
    local rc_val = parts[8] or "0"

    local ki = tonumber(keyinfo_hex, 16) or 0
    local nonce_bytes = ""
    for b in nonce_hex:gmatch("%x%x") do
      nonce_bytes = nonce_bytes .. string.char(tonumber(b, 16))
    end
    local mic_bytes = ""
    for b in mic_hex:gmatch("%x%x") do
      mic_bytes = mic_bytes .. string.char(tonumber(b, 16))
    end

    local step = nil
    local install = (ki & 0x0040) ~= 0
    local ack = (ki & 0x0080) ~= 0
    local mic_f = (ki & 0x0100) ~= 0
    local secure = (ki & 0x0200) ~= 0

    if ack and not mic_f and not install and not secure then step = 1 end
    if not ack and mic_f and not install and not secure then step = 2 end
    if ack and mic_f and install and not secure then step = 3 end
    if not ack and mic_f and not install and secure then step = 4 end

    if step then
      handshake_steps[step] = handshake_steps[step] + 1
      local nonce_str = ""
      if step == 1 then
        anonce = nonce_bytes
        nonce_str = hex_bytes(anonce)
      elseif step == 2 then
        snonce = nonce_bytes
        nonce_str = hex_bytes(snonce)
      end
      if #mic_hex > 0 then mic_value = mic_hex end
      replay_counter = rc_val

      telemetry("handshake_step", '{"step":' .. tostring(step) .. ',"frame":' .. json_escape(frame_num) .. ',"sa":' .. json_escape(sa) .. ',"da":' .. json_escape(da) .. ',"nonce":' .. json_escape(nonce_str) .. ',"mic":' .. json_escape(mic_hex) .. ',"replay_counter":' .. json_escape(tostring(rc_val)) .. ',"key_info_hex":' .. json_escape(keyinfo_hex) .. '}')
      frame_count = frame_count + 1

      if step == 4 then
        local integrity = "valid"
        if mic_hex == "00000000000000000000000000000000" then
          integrity = "invalid_zero_mic"
        end
        telemetry("handshake_complete", '{"total_steps":4,"frames":' .. tostring(frame_count) .. ',"step_counts":{"1":' .. tostring(handshake_steps[1]) .. ',"2":' .. tostring(handshake_steps[2]) .. ',"3":' .. tostring(handshake_steps[3]) .. ',"4":' .. tostring(handshake_steps[4]) .. '},"integrity":' .. json_escape(integrity) .. '}')
      end
    else
      telemetry("eapol_other", '{"frame":' .. json_escape(frame_num) .. ',"key_info":' .. json_escape(keyinfo_hex) .. ',"type":"non_handshake_or_unknown"}')
    end
  end
  f:close()

  telemetry("eapol_summary", '{"total_eapol":' .. tostring(total_eapol) .. ',"handshake_frames":' .. tostring(frame_count) .. ',"steps_found":{"1":' .. tostring(handshake_steps[1]) .. ',"2":' .. tostring(handshake_steps[2]) .. ',"3":' .. tostring(handshake_steps[3]) .. ',"4":' .. tostring(handshake_steps[4]) .. '}}')
end

if not pcap_file then
  telemetry("error", '{"error":"Usage: eapol_analyzer.lua <pcap_file>"}')
  os.exit(1)
end

local f = io.open(pcap_file, "r")
if not f then
  telemetry("error", '{"error":"Cannot open pcap file: ' .. pcap_file .. '"}')
  os.exit(1)
end
f:close()

local ok, err = pcall(analyze_pcap)
if not ok then
  telemetry("error", '{"error":"Analysis failed: ' .. json_escape(tostring(err)) .. '"}')
  os.exit(1)
end

telemetry("complete", '{"file":' .. json_escape(pcap_file) .. '}')
