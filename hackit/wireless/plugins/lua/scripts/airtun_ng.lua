local iface = arg[1]
local server_ip = arg[2] or ""
local port = tonumber(arg[3]) or 5555
local key = arg[4] or "opencode_wireless_key"

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":' .. json_escape(iface) .. ',"bssid":"","ssid":"","channel":"","data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
  io.flush()
end

local tun_iface = "at0"

local function create_tun()
  local cmd = "airtun-ng -a " .. iface .. " -e " .. tun_iface .. " 2>/dev/null &"
  telemetry("tun_create", '{"cmd":' .. json_escape(cmd) .. '}')
  os.execute(cmd)
  os.execute("sleep 2")
  local f = io.popen("ip link show " .. tun_iface .. " 2>/dev/null", "r")
  if f then
    local out = f:read("*a")
    f:close()
    if out and #out > 0 then
      telemetry("tun_created", '{"interface":' .. json_escape(tun_iface) .. '}')
      return true
    end
  end
  telemetry("tun_fail", '{"error":"Failed to create tunnel interface"}')
  return false
end

local function setup_encryption()
  local cmd = "airtun-ng -z 4 -w " .. key .. " -a " .. iface .. " 2>/dev/null &"
  telemetry("encryption_setup", '{"cmd":' .. json_escape(cmd) .. ',"key":' .. json_escape(key) .. '}')
  os.execute(cmd)
  os.execute("sleep 1")
end

local function start_client_mode()
  if not server_ip or #server_ip == 0 then
    telemetry("client_skip", '{"message":"No server IP provided, running in server mode"}')
    return
  end
  local cmd = "airtun-ng -c " .. server_ip .. ":" .. port .. " -w " .. key .. " -a " .. iface .. " 2>/dev/null &"
  telemetry("client_start", '{"cmd":' .. json_escape(cmd) .. ',"server":' .. json_escape(server_ip) .. ',"port":' .. tostring(port) .. '}')
  os.execute(cmd)
end

local function monitor_tun()
  for i = 1, 60 do
    os.execute("sleep 5")
    local f = io.popen("ip -s link show " .. tun_iface .. " 2>/dev/null", "r")
    if f then
      local out = f:read("*a")
      f:close()
      local tx = out:match("TX:.-(%d+)")
      local rx = out:match("RX:.-(%d+)")
      telemetry("tun_stats", '{"tx_bytes":' .. json_escape(tx or "0") .. ',"rx_bytes":' .. json_escape(rx or "0") .. '}')
    end
    local alive = io.popen("pgrep -f 'airtun-ng.*" .. iface .. "' 2>/dev/null", "r")
    if alive then
      local pid = alive:read("*a")
      alive:close()
      if not pid or #pid == 0 then
        telemetry("tun_dead", '{"message":"airtun-ng process died"}')
        break
      end
    end
  end
end

if not iface then
  telemetry("error", '{"error":"Usage: airtun_ng.lua <interface> [server_ip] [port] [key]"}')
  os.exit(1)
end

local ok, err = pcall(function()
  if not create_tun() then os.exit(1) end
  setup_encryption()
  start_client_mode()
  monitor_tun()
end)

if not ok then
  telemetry("error", '{"error":' .. json_escape(tostring(err)) .. '}')
  os.exit(1)
end

telemetry("complete", '{"tun_iface":' .. json_escape(tun_iface) .. '}')
