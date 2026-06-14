local iface = arg[1]
local action = arg[2] or "show"
local value = arg[3] or ""

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":' .. json_escape(iface) .. ',"bssid":"","ssid":"","channel":"","data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
  io.flush()
end

local function get_current_mac()
  local f = io.popen("ip link show " .. iface .. " 2>/dev/null", "r")
  if not f then return nil end
  local out = f:read("*a")
  f:close()
  local mac = out:match("link/ether%s+([%x:]+)")
  return mac
end

local function get_original_mac()
  local f = io.popen("cat /sys/class/net/" .. iface .. "/addr_perm 2>/dev/null", "r")
  if f then
    local mac = f:read("*a")
    f:close()
    if mac and #mac > 0 then return mac:match("[%x:]+") end
  end
  local f2 = io.popen("ethtool -P " .. iface .. " 2>/dev/null | awk '{print $3}'", "r")
  if f2 then
    local mac = f2:read("*a")
    f2:close()
    if mac and #mac > 0 then return mac:match("[%x:]+") end
  end
  return get_current_mac()
end

local function random_mac()
  local r = io.popen("openssl rand -hex 6 2>/dev/null", "r")
  if not r then
    math.randomseed(os.time())
    local bytes = {}
    for i = 1, 6 do bytes[i] = string.format("%02x", math.random(0, 255)) end
    bytes[1] = string.format("%02x", (tonumber(bytes[1], 16) & 0xfe) | 0x02)
    return table.concat(bytes, ":")
  end
  local hex = r:read("*a")
  r:close()
  local mac = hex:gsub("(%x%x)(%x%x)(%x%x)(%x%x)(%x%x)(%x%x)", function(a, b, c, d, e, f)
    local fa = tonumber(a, 16) | 0x02
    fa = fa & 0xfe
    return string.format("%02x:%s:%s:%s:%s:%s", fa, b, c, d, e, f)
  end)
  return mac
end

local function do_change(new_mac)
  telemetry("change_start", '{"new_mac":' .. json_escape(new_mac) .. '}')
  os.execute("ip link set " .. iface .. " down 2>/dev/null")
  os.execute("ip link set " .. iface .. " address " .. new_mac .. " 2>/dev/null")
  os.execute("ip link set " .. iface .. " up 2>/dev/null")
  os.execute("sleep 1")
  local current = get_current_mac()
  if current and current == new_mac then
    telemetry("change_ok", '{"mac":' .. json_escape(current) .. '}')
    return true
  end
  telemetry("change_fail", '{"expected":' .. json_escape(new_mac) .. ',"got":' .. json_escape(current or "nil") .. '}')
  return false
end

local function restore_mac()
  local original = get_original_mac()
  if not original then
    telemetry("restore_fail", '{"error":"Cannot determine original MAC"}')
    return false
  end
  telemetry("restore_start", '{"original_mac":' .. json_escape(original) .. '}')
  os.execute("ip link set " .. iface .. " down 2>/dev/null")
  os.execute("ip link set " .. iface .. " address " .. original .. " 2>/dev/null")
  os.execute("ip link set " .. iface .. " up 2>/dev/null")
  os.execute("sleep 1")
  local current = get_current_mac()
  if current and current == original then
    telemetry("restore_ok", '{"mac":' .. json_escape(current) .. '}')
    return true
  end
  local cmd = "macchanger -p " .. iface .. " 2>/dev/null"
  os.execute(cmd)
  current = get_current_mac()
  telemetry("restore_result", '{"mac":' .. json_escape(current or "") .. '}')
  return true
end

local function show_mac()
  local current = get_current_mac()
  local original = get_original_mac()
  telemetry("mac_show", '{"current":' .. json_escape(current or "unknown") .. ',"original":' .. json_escape(original or "unknown") .. '}')
end

if not iface then
  telemetry("error", '{"error":"Usage: mac_changer.lua <interface> <action> [value]"}')
  os.exit(1)
end

local ok, err = pcall(function()
  if action == "show" then
    show_mac()
  elseif action == "random" then
    local mac = random_mac()
    do_change(mac)
  elseif action == "set" then
    if not value or #value == 0 then
      telemetry("error", '{"error":"No MAC address provided for set action"}')
      os.exit(1)
    end
    do_change(value)
  elseif action == "restore" then
    restore_mac()
  else
    telemetry("error", '{"error":"Unknown action: ' .. action .. '"}')
    os.exit(1)
  end
end)

if not ok then
  telemetry("error", '{"error":' .. json_escape(tostring(err)) .. '}')
  os.exit(1)
end

telemetry("complete", '{"action":' .. json_escape(action) .. '}')
