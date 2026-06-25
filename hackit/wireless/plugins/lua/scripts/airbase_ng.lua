local iface = arg[1]
local ssid = arg[2] or ("AP_" .. tostring(math.floor(os.time() * 1000 % 10000)))
local channel = tonumber(arg[3]) or 6
local wpa2_pass = arg[4] or "password123"

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":' .. json_escape(iface) .. ',"bssid":"","ssid":' .. json_escape(ssid) .. ',"channel":' .. tostring(channel) .. ',"data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
  io.flush()
end

local function write_configs()
  local hostapd_conf = "/tmp/hostapd_" .. iface .. ".conf"
  local dnsmasq_conf = "/tmp/dnsmasq_" .. iface .. ".conf"
  local f = io.open(hostapd_conf, "w")
  if not f then
    telemetry("error", '{"error":"Cannot write hostapd config"}')
    return nil, nil
  end
  f:write("interface=" .. iface .. "\n")
  f:write("driver=nl80211\n")
  f:write("ssid=" .. ssid .. "\n")
  f:write("hw_mode=g\n")
  f:write("channel=" .. channel .. "\n")
  f:write("wpa=2\n")
  f:write("wpa_passphrase=" .. wpa2_pass .. "\n")
  f:write("wpa_key_mgmt=WPA-PSK\n")
  f:write("wpa_pairwise=TKIP CCMP\n")
  f:write("rsn_pairwise=CCMP\n")
  f:write("auth_algs=1\n")
  f:close()
  local d = io.open(dnsmasq_conf, "w")
  if not d then
    telemetry("error", '{"error":"Cannot write dnsmasq config"}')
    return hostapd_conf, nil
  end
  d:write("interface=" .. iface .. "\n")
  d:write("dhcp-range=10.0.0.10,10.0.0.100,12h\n")
  d:write("dhcp-option=3,10.0.0.1\n")
  d:write("dhcp-option=6,10.0.0.1\n")
  d:write("server=8.8.8.8\n")
  d:write("log-queries\n")
  d:write("log-dhcp\n")
  d:close()
  telemetry("config_written", '{"hostapd":' .. json_escape(hostapd_conf) .. ',"dnsmasq":' .. json_escape(dnsmasq_conf) .. '}')
  return hostapd_conf, dnsmasq_conf
end

local function setup_interface()
  os.execute("ip link set " .. iface .. " down 2>/dev/null")
  os.execute("ip addr add 10.0.0.1/24 dev " .. iface .. " 2>/dev/null")
  os.execute("ip link set " .. iface .. " up 2>/dev/null")
  telemetry("interface_setup", '{"ip":"10.0.0.1/24"}')
end

local function run_airbase()
  local cmd = "airbase-ng -e " .. ssid .. " -c " .. channel .. " -W 1 " .. iface .. " 2>/dev/null &"
  telemetry("airbase_start", '{"cmd":' .. json_escape(cmd) .. '}')
  os.execute(cmd)
  os.execute("sleep 1")
end

local function run_services(hostapd_conf, dnsmasq_conf)
  local cmd_h = "hostapd " .. hostapd_conf .. " 2>/dev/null &"
  local cmd_d = "dnsmasq -C " .. dnsmasq_conf .. " 2>/dev/null &"
  os.execute(cmd_h)
  os.execute(cmd_d)
  telemetry("services_started", '{"hostapd":"started","dnsmasq":"started"}')
end

local function capture_handshakes()
  local f = io.popen("tcpdump -i " .. iface .. " -nn -c 100 port 88 or port 67 or port 68 2>/dev/null", "r")
  if not f then return end
  local captured = 0
  while true do
    local line = f:read("*l")
    if not line then break end
    if line:find("EAPOL") or line:find("eapol") or line:find("SAP") then
      captured = captured + 1
      telemetry("handshake", '{"count":' .. tostring(captured) .. ',"detail":' .. json_escape(line:sub(1, 150)) .. '}')
    end
    if line:find("DHCP") then
      telemetry("dhcp_lease", '{"detail":' .. json_escape(line:sub(1, 150)) .. '}')
    end
  end
  f:close()
end

if not iface then
  telemetry("error", '{"error":"Usage: airbase_ng.lua <interface> [ssid] [channel] [wpa2_pass]"}')
  os.exit(1)
end

local ok, err = pcall(function()
  local hp_conf, dns_conf = write_configs()
  if not hp_conf then os.exit(1) end
  setup_interface()
  run_airbase()
  if dns_conf then run_services(hp_conf, dns_conf) end
  capture_handshakes()
end)

if not ok then
  telemetry("error", '{"error":' .. json_escape(tostring(err)) .. '}')
  os.exit(1)
end

telemetry("complete", '{"ssid":' .. json_escape(ssid) .. ',"channel":' .. tostring(channel) .. '}')
