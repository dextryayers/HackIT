local iface = arg[1]
local output_prefix = arg[2] or "/tmp/airodump_" .. iface
local channel = arg[3] or ""

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":' .. json_escape(iface) .. ',"bssid":"","ssid":"","channel":' .. json_escape(channel) .. ',"data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
  io.flush()
end

local function check_monitor_mode()
  local f = io.popen("iw dev " .. iface .. " info 2>/dev/null")
  if not f then return false end
  local out = f:read("*a")
  f:close()
  if out:find("type monitor") then return true end
  telemetry("monitor_fail", '{"error":"Interface not in monitor mode"}')
  return false
end

local function parse_csv_line(line)
  local parts = {}
  for part in line:gmatch('([^,]+)') do
    table.insert(parts, part:match('^%s*(.-)%s*$'))
  end
  return parts
end

local function run_airodump()
  local cmd = "airodump-ng --write " .. output_prefix .. " --output-format csv,pcap " .. iface
  if channel and #channel > 0 then
    cmd = cmd .. " --channel " .. channel
  end
  cmd = cmd .. " 2>/dev/null &"
  telemetry("airodump_start", '{"cmd":' .. json_escape(cmd) .. ',"output":' .. json_escape(output_prefix) .. '}')
  local pid = io.popen("echo $!", "r")
  os.execute(cmd .. " &")
  if pid then
    local p = pid:read("*a")
    pid:close()
    telemetry("airodump_pid", '{"pid":' .. json_escape(p:match("%d+") or "unknown") .. '}')
  end
end

local function parse_csv()
  local csv_file = output_prefix .. "-01.csv"
  local seen_aps = {}
  local seen_clients = {}
  local in_clients = false
  for i = 1, 30 do
    os.execute("sleep 2")
    local f = io.open(csv_file, "r")
    if not f then
      telemetry("csv_wait", '{"attempt":' .. tostring(i) .. ',"file":' .. json_escape(csv_file) .. '}')
      goto continue
    end
    local ap_section = true
    for line in f:lines() do
      if line:find("^BSSID,") or line:find("^Station MAC,") then
        if line:find("^Station MAC,") then ap_section = false end
        goto nextline
      end
      if #line < 10 then goto nextline end
      local parts = parse_csv_line(line)
      if #parts < 6 then goto nextline end
      if ap_section then
        local b = parts[1]
        if b and b:match("^[%x:]+$") and #b == 17 then
          local pwr = parts[3] or "0"
          local ch = parts[5] or "0"
          local enc = (parts[6] or ""):gsub('"', '')
          local essid = (parts[13] or ""):gsub('"', '')
          if not seen_aps[b] then
            seen_aps[b] = true
            telemetry("ap_found", '{"bssid":' .. json_escape(b) .. ',"power":' .. json_escape(pwr) .. ',"channel":' .. json_escape(ch) .. ',"encryption":' .. json_escape(enc) .. ',"ssid":' .. json_escape(essid) .. '}')
          end
        end
      else
        local mac = parts[0] or parts[1]
        if mac and mac:match("^[%x:]+$") and #mac == 17 then
          local bssid_col = parts[client_bssid_col or 5] or ""
          local pwr = parts[3] or "0"
          if not seen_clients[mac] then
            seen_clients[mac] = true
            telemetry("client_found", '{"mac":' .. json_escape(mac) .. ',"bssid":' .. json_escape(bssid_col) .. ',"power":' .. json_escape(pwr) .. '}')
          end
        end
      end
      ::nextline::
    end
    f:close()
    telemetry("csv_parse", '{"aps_found":' .. tostring(#seen_aps) .. ',"clients_found":' .. tostring(#seen_clients) .. '}')
    ::continue::
  end
end

local function monitor_pmkid_handshakes()
  local pcap_file = output_prefix .. "-01.cap"
  for i = 1, 30 do
    os.execute("sleep 5")
    local f = io.popen("tshark -r " .. pcap_file .. " -Y 'eapol' -T fields -e wlan.sa -e wlan.da -e eapol.keydes.info 2>/dev/null | sort -u | head -20")
    if f then
      local out = f:read("*a")
      f:close()
      if out and #out > 0 then
        for line in out:gmatch("[^\n]+") do
          local sa, da, kinfo = line:match("([%x:]+)%s+([%x:]+)%s+(.+)")
          if sa and da then
            telemetry("eapol_capture", '{"source":' .. json_escape(sa) .. ',"dest":' .. json_escape(da) .. ',"key_info":' .. json_escape(kinfo or "") .. '}')
          end
        end
      end
    end
    local h = io.popen("hcxpcapngtool -o /dev/stdout " .. pcap_file .. " 2>/dev/null | head -5")
    if h then
      local hout = h:read("*a")
      h:close()
      if hout and #hout > 0 then
        telemetry("pmkid_found", '{"hash":' .. json_escape(hout:sub(1, 200)) .. '}')
      end
    end
  end
end

if not iface then
  telemetry("error", '{"error":"Usage: airodump_ng.lua <interface> [output_prefix] [channel]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Monitor mode required on ' .. iface .. '"}')
  os.exit(1)
end

local ok, err = pcall(function()
  run_airodump()
  parse_csv()
  monitor_pmkid_handshakes()
end)

if not ok then
  telemetry("error", '{"error":' .. json_escape(tostring(err)) .. '}')
  os.exit(1)
end

telemetry("complete", '{"output_prefix":' .. json_escape(output_prefix) .. '}')
