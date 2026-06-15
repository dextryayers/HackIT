-- Security Header Analyzer
local input = arg[1] or "{}"

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

local function json_decode(str)
  local function skip_ws(s, i)
    while i <= #s do
      local c = s:sub(i,i)
      if c == ' ' or c == '\t' or c == '\n' or c == '\r' then i = i + 1
      else break end
    end
    return i
  end
  local function parse_val(s, i)
    i = skip_ws(s, i)
    if i > #s then return nil, i end
    local c = s:sub(i,i)
    if c == '"' then
      local str = ""
      i = i + 1
      while i <= #s do
        local cc = s:sub(i,i)
        if cc == '"' then return str, i + 1 end
        if cc == '\\' then
          i = i + 1
          local esc = s:sub(i,i)
          if esc == '"' then str = str .. '"'
          elseif esc == '\\' then str = str .. '\\'
          elseif esc == '/' then str = str .. '/'
          elseif esc == 'n' then str = str .. '\n'
          elseif esc == 'r' then str = str .. '\r'
          elseif esc == 't' then str = str .. '\t'
          elseif esc == 'b' then str = str .. '\b'
          elseif esc == 'f' then str = str .. '\f'
          elseif esc == 'u' then
            local hex = s:sub(i+1, i+4)
            str = str .. utf8.char(tonumber(hex, 16) or 63)
            i = i + 4
          end
          i = i + 1
        else
          str = str .. cc
          i = i + 1
        end
      end
      return nil, i
    elseif c == '{' then
      local obj = {}
      i = i + 1
      i = skip_ws(s, i)
      if s:sub(i,i) == '}' then return obj, i + 1 end
      while true do
        i = skip_ws(s, i)
        local key, ni = parse_val(s, i)
        if not key then break end
        i = skip_ws(s, ni)
        if s:sub(i,i) ~= ':' then break end
        i = i + 1
        local val, ni2 = parse_val(s, i)
        if not val then break end
        obj[key] = val
        i = skip_ws(s, ni2)
        local nc = s:sub(i,i)
        if nc == '}' then return obj, i + 1 end
        if nc ~= ',' then break end
        i = i + 1
      end
      return nil, i
    elseif c == '[' then
      local arr = {}
      i = i + 1
      i = skip_ws(s, i)
      if s:sub(i,i) == ']' then return arr, i + 1 end
      while true do
        local val, ni = parse_val(s, i)
        if val == nil then break end
        table.insert(arr, val)
        i = skip_ws(s, ni)
        local nc = s:sub(i,i)
        if nc == ']' then return arr, i + 1 end
        if nc ~= ',' then break end
        i = i + 1
      end
      return nil, i
    elseif c == 't' and s:sub(i,i+3) == 'true' then return true, i + 4
    elseif c == 'f' and s:sub(i,i+4) == 'false' then return false, i + 5
    elseif c == 'n' and s:sub(i,i+3) == 'null' then return nil, i + 4
    else
      local num_str = ""
      while i <= #s do
        local cc = s:sub(i,i)
        if (cc >= '0' and cc <= '9') or cc == '-' or cc == '+' or cc == '.' or cc == 'e' or cc == 'E' then
          num_str = num_str .. cc
          i = i + 1
        else break end
      end
      if num_str ~= "" then
        local n = tonumber(num_str)
        return n, i
      end
      return nil, i
    end
  end
  local val, _ = parse_val(str, 1)
  return val
end

local result = { status = "ok" }
local ok, err = pcall(function()
  local headers_raw = json_decode(input)
  if not headers_raw then headers_raw = {} end

  local function header_lower(name)
    if type(headers_raw) == "table" then
      for k, v in pairs(headers_raw) do
        if k:lower() == name:lower() then return v end
      end
    end
    return nil
  end

  local checks = {
    { name = "Content-Security-Policy", risk = "HIGH" },
    { name = "X-Frame-Options", risk = "HIGH" },
    { name = "Strict-Transport-Security", risk = "HIGH" },
    { name = "X-Content-Type-Options", risk = "HIGH" },
    { name = "Referrer-Policy", risk = "MEDIUM" },
    { name = "Permissions-Policy", risk = "MEDIUM" },
    { name = "X-XSS-Protection", risk = "MEDIUM" },
    { name = "Feature-Policy", risk = "MEDIUM" },
    { name = "Access-Control-Allow-Origin", risk = "MEDIUM" },
    { name = "Set-Cookie", risk = "MEDIUM" },
  }

  local unsafe_values = {
    ["x-frame-options"] = { "deny", "sameorigin" },
    ["x-content-type-options"] = { "nosniff" },
    ["x-xss-protection"] = { "1; mode=block" },
    ["referrer-policy"] = { "no-referrer", "strict-origin-when-cross-origin", "same-origin" },
  }

  local results_list = {}
  local score = 0
  local max_score = #checks * 10

  for _, check in ipairs(checks) do
    local val = header_lower(check.name)
    local entry = { header = check.name, present = val ~= nil }
    if val then
      entry.value = val:sub(1, 100)
      entry.truncated = #val > 100
      local lower_val = val:lower()
      local safe = unsafe_values[check.name:lower()]
      local is_secure = false
      if safe then
        for _, sv in ipairs(safe) do
          if lower_val:find(sv) then is_secure = true; break end
        end
      end
      if check.name == "Content-Security-Policy" then
        if lower_val:find("default%-src") or lower_val:find("script%-src") then
          is_secure = true
        end
      end
      if check.name == "Strict-Transport-Security" then
        if lower_val:find("max%-age") then is_secure = true end
      end
      if check.name == "Permissions-Policy" or check.name == "Feature-Policy" then
        is_secure = true
      end
      if check.name == "Access-Control-Allow-Origin" then
        if val == "*" or val == "" then
          entry.rating = "MEDIUM"
          entry.reason = "insecure value"
          score = score + 2
        else
          is_secure = true
        end
      end
      if check.name == "Set-Cookie" then
        if lower_val:find("secure") and lower_val:find("httponly") then
          is_secure = true
        else
          entry.rating = "MEDIUM"
          entry.reason = "insecure value"
          score = score + 2
        end
      end
      if check.name == "X-XSS-Protection" then
        if lower_val:find("0") then
          entry.rating = "MEDIUM"
          entry.reason = "insecure value"
          score = score + 2
        else
          is_secure = true
        end
      end
      if is_secure then
        entry.rating = "PASS"
        score = score + 10
      elseif not entry.rating then
        entry.rating = "PASS"
        score = score + 10
      end
    else
      entry.rating = "HIGH"
      entry.reason = "missing"
    end
    table.insert(results_list, entry)
  end

  result.headers = results_list

  local overall = (score / max_score) * 10
  result.score = math.floor(overall * 10 + 0.5) / 10
  if overall >= 9 then result.grade = "A"
  elseif overall >= 7 then result.grade = "B"
  elseif overall >= 5 then result.grade = "C"
  elseif overall >= 3 then result.grade = "D"
  elseif overall >= 1 then result.grade = "E"
  else result.grade = "F" end
end)

if not ok then
  print('{"status":"error","error":"' .. tostring(err):gsub('"', '\\"'):gsub('\n', '\\n') .. '"}')
  return
end

print(json_encode(result))
