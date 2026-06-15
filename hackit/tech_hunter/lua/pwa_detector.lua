-- PWA Detector
local body = arg[1] or ""

local function json_encode(val)
  local function enc(v, buf)
    local t = type(v)
    if t == "string" then
      buf[#buf+1] = '"'
      for i = 1, #v do
        local c = v:sub(i,i)
        if c == '"' then buf[#buf+1] = '\\"'
        elseif c == '\\' then buf[#buf+1] = '\\\\'
        elseif c == '\n' then buf[#buf+1] = '\\n'
        elseif c == '\r' then buf[#buf+1] = '\\r'
        elseif c == '\t' then buf[#buf+1] = '\\t'
        elseif c == '\b' then buf[#buf+1] = '\\b'
        elseif c == '\f' then buf[#buf+1] = '\\f'
        else buf[#buf+1] = c end
      end
      buf[#buf+1] = '"'
    elseif t == "number" or t == "boolean" then buf[#buf+1] = tostring(v)
    elseif t == "table" then
      local is_arr = true
      local max_k = 0
      for k, _ in pairs(v) do
        if type(k) ~= "number" or k ~= math.floor(k) or k < 1 then is_arr = false; break end
        if k > max_k then max_k = k end
      end
      if is_arr and max_k == #v then
        buf[#buf+1] = '['
        for i = 1, #v do
          if i > 1 then buf[#buf+1] = ',' end; enc(v[i], buf)
        end
        buf[#buf+1] = ']'
      else
        buf[#buf+1] = '{'
        local first = true
        for k, val in pairs(v) do
          if not first then buf[#buf+1] = ',' end; first = false
          enc(tostring(k), buf); buf[#buf+1] = ':'; enc(val, buf)
        end
        buf[#buf+1] = '}'
      end
    else buf[#buf+1] = 'null' end
  end
  local buf = {}; enc(val, buf); return table.concat(buf)
end

local result = { status = "ok" }
local ok, err = pcall(function()
  local signals = {}

  -- Web App Manifest
  local pat_manifest = '<link[^>]-rel%s*=%s*["\']manifest["\'][^>]-href%s*=%s*["\']([^"\']-)["\']'
  local _, _, manifest_href = body:find(pat_manifest)
  if not manifest_href then
    local pat_manifest2 = '<link[^>]-href%s*=%s*["\']([^"\']-)["\'][^>]-rel%s*=%s*["\']manifest["\']'
    _, _, manifest_href = body:find(pat_manifest2)
  end
  signals.manifest = { present = manifest_href ~= nil, href = manifest_href or "" }

  -- Service Worker (via link or script reference)
  local sw_link = false
  local pat_sw = '<link[^>]-rel%s*=%s*["\']serviceworker["\']'
  if body:find(pat_sw) then sw_link = true end
  local sw_script = false
  if body:find("navigator%.serviceWorker") or body:find("service%-worker") then sw_script = true end
  local sw_file_ref = body:find("service%-worker%.js") or body:find("sw%.js")
  signals.service_worker = { detected = sw_link or sw_script or (sw_file_ref ~= nil), link_rel = sw_link, script_ref = sw_script, file_ref = sw_file_ref ~= nil }

  -- Apple mobile-web-app-capable
  local pat_apple = '<meta[^>]-name%s*=%s*["\']apple%-mobile%-web%-app%-capable["\']'
  local apple_capable = body:find(pat_apple) ~= nil
  local apple_content = ""
  if apple_capable then
    local _, _, ac = body:find('<meta[^>]-name%s*=%s*["\']apple%-mobile%-web%-app%-capable["\']([^>]-)content%s*=%s*["\']([^"\']-)["\']')
    if not ac then
      local _, _, ac2 = body:find('<meta[^>]-content%s*=%s*["\']([^"\']-)["\'][^>]-name%s*=%s*["\']apple%-mobile%-web%-app%-capable["\']')
      if ac2 then apple_content = ac2 end
    else
      apple_content = ac
    end
  end
  signals.apple_mobile_web_app_capable = { present = apple_capable, content = apple_content }

  -- Theme color
  local pat_theme = '<meta[^>]-name%s*=%s*["\']theme%-color["\'][^>]-content%s*=%s*["\']([^"\']-)["\']'
  local _, _, theme_color = body:find(pat_theme)
  if not theme_color then
    local pat_theme2 = '<meta[^>]-content%s*=%s*["\']([^"\']-)["\'][^>]-name%s*=%s*["\']theme%-color["\']'
    _, _, theme_color = body:find(pat_theme2)
  end
  signals.theme_color = { present = theme_color ~= nil, color = theme_color or "" }

  -- Apple status bar style
  local pat_status = '<meta[^>]-name%s*=%s*["\']apple%-mobile%-web%-app%-status%-bar%-style["\']'
  local status_bar = body:find(pat_status) ~= nil
  local status_content = ""
  if status_bar then
    local _, _, sc = body:find('<meta[^>]-name%s*=%s*["\']apple%-mobile%-web%-app%-status%-bar%-style["\']([^>]-)content%s*=%s*["\']([^"\']-)["\']')
    if not sc then
      local _, _, sc2 = body:find('<meta[^>]-content%s*=%s*["\']([^"\']-)["\'][^>]-name%s*=%s*["\']apple%-mobile%-web%-app%-status%-bar%-style["\']')
      if sc2 then status_content = sc2 end
    else
      status_content = sc
    end
  end
  signals.apple_status_bar_style = { present = status_bar, content = status_content }

  -- Offline references
  signals.offline_refs = {
    offline_html = body:find("offline%.html") ~= nil,
    service_worker_js = body:find("service%-worker%.js") ~= nil,
    cache_manifest = body:find("cache%-manifest") ~= nil
  }

  -- Score
  local score = 0
  if manifest_href then score = score + 3 end
  if signals.service_worker.detected then score = score + 3 end
  if apple_capable then score = score + 2 end
  if theme_color then score = score + 1 end
  if status_bar then score = score + 1 end

  signals.score = score
  if score >= 7 then
    result.pwa_readiness = "Full PWA"
  elseif score >= 3 then
    result.pwa_readiness = "Partial"
  else
    result.pwa_readiness = "Not PWA"
  end

  result.signals = signals
end)

if not ok then
  print('{"status":"error","error":"' .. tostring(err):gsub('"', '\\"'):gsub('\n', '\\n') .. '"}')
  return
end

print(json_encode(result))
