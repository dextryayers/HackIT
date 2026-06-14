local iface = arg[1]
local channel = tonumber(arg[2]) or 0

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":' .. json_escape(iface) .. ',"bssid":"","ssid":"","channel":' .. tostring(channel) .. ',"data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
  io.flush()
end

local function check_monitor_mode()
  local f = io.popen("iw dev " .. iface .. " info 2>/dev/null")
  if not f then return false end
  local out = f:read("*a")
  f:close()
  return out:find("type monitor") ~= nil
end

local function set_channel()
  if channel > 0 then
    os.execute("iw dev " .. iface .. " set channel " .. channel .. " 2>/dev/null")
    telemetry("channel_set", '{"channel":' .. tostring(channel) .. '}')
  end
end

local function parse_rsn(hex_data)
  if not hex_data then return {} end
  local result = {}
  local akms = {["00-0f-ac-01"] = "802.1X", ["00-0f-ac-02"] = "PSK", ["00-0f-ac-03"] = "FT/802.1X", ["00-0f-ac-04"] = "FT/PSK", ["00-0f-ac-05"] = "SAE", ["00-0f-ac-06"] = "FT/SAE", ["00-0f-ac-07"] = "PSK/SAE", ["00-0f-ac-08"] = "FT/PSK/SAE"}
  local ciphers = {["00-0f-ac-01"] = "WEP-40", ["00-0f-ac-02"] = "TKIP", ["00-0f-ac-03"] = "WRAP", ["00-0f-ac-04"] = "CCMP", ["00-0f-ac-05"] = "WEP-104", ["00-0f-ac-06"] = "BIP-CMAC-128", ["00-0f-ac-07"] = "GCMP-128", ["00-0f-ac-08"] = "GCMP-256", ["00-0f-ac-09"] = "CCMP-256", ["00-0f-ac-10"] = "BIP-GMAC-128", ["00-0f-ac-11"] = "BIP-GMAC-256", ["00-0f-ac-12"] = "BIP-CMAC-256"}
  if hex_data:find("00-0f-ac-05") then result.sae = true end
  if hex_data:find("00-0f-ac-07") then result.sae = true end
  if hex_data:find("00-0f-ac-08") then result.sae = true end
  if hex_data:find("00-0f-ac-06") then result.sae = true end
  local group_mgmt = hex_data:match("00%-0f%-ac%-(%d+)")
  if group_mgmt then
    local g = ciphers["00-0f-ac-" .. group_mgmt]
    if g then result.group_mgmt = g end
  end
  return result
end

local function sniff_beacons()
  local cmd = "tshark -i " .. iface .. " -Y 'wlan.fc.type_subtype == 8' -T fields -e wlan.sa -e wlan.ssid -e wlan_rsn.ie -e radiotap.dbm_antsignal -e wlan.bssid 2>/dev/null"
  telemetry("sniff_start", '{"cmd":' .. json_escape(cmd) .. '}')
  local f = io.popen(cmd, "r")
  if not f then
    telemetry("sniff_fail", '{"error":"Failed to start tshark"}')
    return
  end
  local wpa3_aps = {}
  local trans_mode_aps = {}
  for i = 1, 30 do
    local line = f:read("*l")
    if not line then break end
    if line and #line > 10 then
      local sa, ssid, rsn, signal, bssid = line:match("([%x:]+)%s+(.-)%s+([%x:%-]+)%s+([%-%d]+)%s+([%x:]+)")
      if not bssid then bssid = sa end
      if not sa then
        local parts = {}
        for p in line:gmatch("[^%s]+") do table.insert(parts, p) end
        sa = parts[1]
        if #parts >= 4 then
          ssid = parts[2] or ""
          rsn = parts[3] or ""
          signal = parts[4] or "0"
          bssid = #parts >= 5 and parts[5] or sa
        end
      end
      if rsn then
        local rsn_info = parse_rsn(rsn)
        if rsn_info.sae then
          if not wpa3_aps[bssid] then
            wpa3_aps[bssid] = true
            telemetry("wpa3_ap", '{"bssid":' .. json_escape(bssid) .. ',"ssid":' .. json_escape(ssid or "") .. ',"signal":' .. json_escape(signal or "0") .. ',"group_mgmt":' .. json_escape(rsn_info.group_mgmt or "") .. '}')
          end
        end
        if rsn:find("00-0f-ac-02") and rsn:find("00-0f-ac-05") then
          if not trans_mode_aps[bssid] then
            trans_mode_aps[bssid] = true
            telemetry("wpa3_transition", '{"bssid":' .. json_escape(bssid) .. ',"ssid":' .. json_escape(ssid or "") .. ',"message":"WPA3 Transition Mode detected - accepts WPA2 and WPA3"}')
          end
        end
      end
    end
  end
  f:close()
  telemetry("sniff_result", '{"wpa3_aps":' .. tostring(#wpa3_aps) .. ',"transition_mode":' .. tostring(#trans_mode_aps) .. '}')
  return wpa3_aps
end

local function sniff_sae_frames()
  local cmd = "tshark -i " .. iface .. " -Y 'wlan.fc.type_subtype == 0 or wlan.fc.type_subtype == 1 or wlan.fc.type_subtype == 2' -T fields -e frame.number -e wlan.sa -e wlan.da -e wlan.fc.type_subtype 2>/dev/null"
  local f = io.popen(cmd, "r")
  if not f then return end
  local sae_commit = 0
  local sae_confirm = 0
  for i = 1, 50 do
    local line = f:read("*l")
    if not line then break end
    if line:find("0x0000") or line:find("0x0001") or line:find("0x0002") then
      local sub_type = line:match("(%d+)$")
      if sub_type == "0" then
        sae_commit = sae_commit + 1
        telemetry("sae_commit", '{"detail":' .. json_escape(line:sub(1, 150)) .. '}')
      elseif sub_type == "1" then
        sae_confirm = sae_confirm + 1
        telemetry("sae_confirm", '{"detail":' .. json_escape(line:sub(1, 150)) .. '}')
      end
    end
  end
  f:close()
  telemetry("sae_summary", '{"commit_frames":' .. tostring(sae_commit) .. ',"confirm_frames":' .. tostring(sae_confirm) .. '}')
end

if not iface then
  telemetry("error", '{"error":"Usage: wpa3_sae.lua <interface> [channel]"}')
  os.exit(1)
end

if not check_monitor_mode() then
  telemetry("error", '{"error":"Monitor mode required on ' .. iface .. '"}')
  os.exit(1)
end

local ok, err = pcall(function()
  set_channel()
  sniff_beacons()
  sniff_sae_frames()
end)

if not ok then
  telemetry("error", '{"error":' .. json_escape(tostring(err)) .. '}')
  os.exit(1)
end

telemetry("complete", '{"channel":' .. tostring(channel) .. '}')
