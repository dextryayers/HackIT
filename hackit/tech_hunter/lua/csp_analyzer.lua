-- CSP Analyzer
local input = arg[1] or ""

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
        else buf[#buf+1] = c
        end
      end
      buf[#buf+1] = '"'
    elseif t == "number" or t == "boolean" then
      buf[#buf+1] = tostring(v)
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
          if i > 1 then buf[#buf+1] = ',' end
          enc(v[i], buf)
        end
        buf[#buf+1] = ']'
      else
        buf[#buf+1] = '{'
        local first = true
        for k, val in pairs(v) do
          if not first then buf[#buf+1] = ',' end
          first = false
          enc(tostring(k), buf)
          buf[#buf+1] = ':'
          enc(val, buf)
        end
        buf[#buf+1] = '}'
      end
    else
      buf[#buf+1] = 'null'
    end
  end
  local buf = {}
  enc(val, buf)
  return table.concat(buf)
end

local critical = { ["default-src"] = true, ["script-src"] = true, ["object-src"] = true, ["base-uri"] = true }
local result = {}
result.status = "ok"

local ok, err = pcall(function()
  result.input_length = #input
  local directives = {}
  local found_dirs = {}
  for dir in input:gmatch("([^;]+)") do
    local dname, dval = dir:match("^%s*([%w%-]+)%s*(.*)$")
    if dname then
      local dn = dname:lower()
      local entry = { directive = dn, value = dval and dval:match("^%s*(.-)%s*$") or "" }
      table.insert(directives, entry)
      found_dirs[dn] = true
    end
  end
  result.directives = directives
  local missing = {}
  for c, _ in pairs(critical) do
    if not found_dirs[c] then table.insert(missing, c) end
  end
  result.missing_critical = missing

  if #directives == 0 then
    result.rating = "None"
  elseif not found_dirs["default-src"] and not found_dirs["script-src"] then
    result.rating = "Weak"
  elseif found_dirs["default-src"] or found_dirs["script-src"] then
    if found_dirs["object-src"] and found_dirs["base-uri"] then
      result.rating = "Strong"
    else
      result.rating = "Moderate"
    end
  else
    result.rating = "Weak"
  end
end)

if not ok then
  print('{"status":"error","error":"' .. tostring(err):gsub('"', '\\"'):gsub('\n', '\\n') .. '"}')
  return
end

print(json_encode(result))
