local iface = arg[1]
local bssid = arg[2] or ""
local timeout = tonumber(arg[3]) or 60

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":' .. json_escape(iface) .. ',"bssid":' .. json_escape(bssid) .. ',"ssid":"","channel":"","data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
  io.flush()
end

local function check_monitor_mode()
  local f = io.popen("iw dev " .. iface .. " info 2>/dev/null")
  if not f then return false end
  local out = f:read("*a")
  f:close()
  return out:find("type monitor") ~= nil
end

local clients = {}
local signal_history = {}

local function normalize_mac(mac)
  if not mac then return nil end
  return mac:lower():gsub("-", ":")
end

local function parse_probe_request(line)
  local sa = line:match("SA:([%x:]+)")
  local ssid = line:match("Probe Request%s+%([^)]+%)%s+(.+)") or line:match("SSID:[%s]+([^\n]+)")
  if not sa then
    sa = line:match("([%x:][%x:]:[%x:][%x:]:[%x:][%x:]:[%x:][%x:]:[%x:][%x:]:[%x:][%x:])")
  end
  if sa then
    sa = normalize_mac(sa)
    if not clients[sa] then
      clients[sa] = {first_seen = os.time(), probes = {}, signals = {}}
    end
    if ssid and ssid ~= "" then
      ssid = ssid:gsub("^%s*(.-)%s*$", "%1")
      clients[sa].probes[ssid] = (clients[sa].probes[ssid] or 0) + 1
    end
  end
end

local function parse_data_frame(line)
  local src = line:match("SA:([%x:]+)")
  local dst = line:match("DA:([%x:]+)")
  local sig = line:match("signal:([%-%d]+)")
  if not src then
    src = line:match("([%x:][%x:]:[%x:][%x:]:[%x:][%x:]:[%x:][%x:]:[%x:][%x:]:[%x:][%x:])")
  end
  if src then
    src = normalize_mac(src)
    if not clients[src] then
      clients[src] = {first_seen = os.time(), probes = {}, signals = {}}
    end
    if sig then
      local s = tonumber(sig)
      table.insert(clients[src].signals, s)
      if not signal_history[src] then signal_history[src] = {} end
      table.insert(signal_history[src], {time = os.time(), signal = s})
      if #signal_history[src] > 100 then table.remove(signal_history[src], 1) end
    end
    if bssid and #bssid > 0 and dst then
      if normalize_mac(dst) == normalize_mac(bssid) then
        telemetry("client_active", '{"mac":' .. json_escape(src) .. ',"destination":' .. json_escape(dst) .. ',"signal":' .. json_escape(sig or "0") .. '}')
      end
    end
  end
end

local function parse_tshark_output(line)
  if line:find("Probe Request") or line:find("Probe") then
    parse_probe_request(line)
  else
    parse_data_frame(line)
  end
end

local function run_sniffer()
  local cmd = "tshark -i " .. iface .. " -Y 'wlan.fc.type == 0 and (wlan.fc.type_subtype == 4 or wlan.fc.type_subtype == 8 or wlan.fc.type_subtype == 32)' -T fields -e frame.time_relative -e wlan.sa -e wlan.da -e radiotap.dbm_antsignal -e wlan.ssid 2>/dev/null"
  if bssid and #bssid > 0 then
    cmd = "tshark -i " .. iface .. " -Y '(wlan.fc.type == 0) and (wlan.addr1==" .. bssid .. " or wlan.addr2==" .. bssid .. " or wlan.addr3==" .. bssid .. ")' -T fields -e frame.time_relative -e wlan.sa -e wlan.da -e radiotap.dbm_antsignal 2>/dev/null"
  end
  telemetry("sniff_start", '{"cmd":' .. json_escape(cmd) .. ',"timeout":' .. tostring(timeout) .. '}')
  local f = io.popen(cmd, "r")
  if not f then
    telemetry("sniff_fail", '{"error":"Failed to start tshark"}')
    return
  end
  local start = os.time()
  while os.time() - start < timeout do
    local line = f:read("*l")
    if not line then break end
    if line and #line > 5 then
      parse_tshark_output(line)
    end
    if os.time() - start > timeout then break end
  end
  f:close()
end

local function report_clients()
  local count = 0
  for mac, info in pairs(clients) do
    count = count + 1
    local avg_sig = 0
    if #info.signals > 0 then
      for _, s in ipairs(info.signals) do avg_sig = avg_sig + s end
      avg_sig = avg_sig / #info.signals
    end
    local probe_list = ""
    for ssid, cnt in pairs(info.probes) do
      probe_list = probe_list .. ssid .. "(" .. cnt .. ") "
    end
    local elapsed = os.time() - info.first_seen
    telemetry("client_report", '{"mac":' .. json_escape(mac) .. ',"probes":' .. json_escape(probe_list) .. ',"avg_signal":' .. tostring(avg_sig) .. ',"signals_count":' .. tostring(#info.signals) .. ',"first_seen_sec":' .. tostring(elapsed) .. ',"active":' .. tostring(elapsed < 30) .. '}')
  end
  telemetry("client_summary", '{"total_clients":' .. tostring(count) .. '}')
end

if not iface then
  telemetry("error", '{"error":"Usage: client_hunt.lua <interface> [bssid] [timeout]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Monitor mode required on ' .. iface .. '"}')
  os.exit(1)
end

local ok, err = pcall(function()
  run_sniffer()
  report_clients()
end)

if not ok then
  telemetry("error", '{"error":' .. json_escape(tostring(err)) .. '}')
  os.exit(1)
end

telemetry("complete", '{"bssid":' .. json_escape(bssid) .. '}')
