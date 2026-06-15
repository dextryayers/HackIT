-- Link Extractor
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
  local categories = { scripts = {}, styles = {}, images = {}, anchors = {}, iframes = {}, media = {}, forms = {}, other = {} }
  local category_map = {
    script = "scripts", link = "styles", img = "images", a = "anchors",
    iframe = "iframes", video = "media", audio = "media", source = "media", embed = "media",
    form = "forms"
  }

  local function is_external(url)
    if not url or url == "" then return false end
    if url:sub(1,2) == "//" then return true end
    if url:sub(1,1) == "/" or url:sub(1,1) == "#" or url:sub(1,1) == "?" then return false end
    if url:match("^[%w%+%-]+:") then
      if url:match("^https?://") or url:match("^//") then return true end
      return false
    end
    return false
  end

  local tags_with_attrs = {
    script = "src", link = "href", img = "src", a = "href",
    iframe = "src", video = "src", audio = "src", source = "src",
    embed = "src", form = "action"
  }

  for tag, attr in pairs(tags_with_attrs) do
    local cat = category_map[tag] or "other"
    local pattern = "<" .. tag .. "[^>]*" .. attr .. "%s*=%s*['\"]([^'\"]+)['\"]"
    local pos = 1
    while true do
      local s, e, url = body:find(pattern, pos)
      if not s then break end
      pos = e + 1
      if url and url ~= "" then
        table.insert(categories[cat], { url = url, tag = tag, external = is_external(url), attr = attr })
      end
    end
    local pattern2 = "<" .. tag .. "[^>]*" .. attr .. "%s*=%s*([^%s>'\"]+)"
    local pos2 = 1
    while true do
      local s, e, url = body:find(pattern2, pos2)
      if not s then break end
      pos2 = e + 1
      if url and url ~= "" and not url:match("^['\"]") then
        local seen = false
        for _, v in ipairs(categories[cat]) do if v.url == url then seen = true; break end end
        if not seen then
          table.insert(categories[cat], { url = url, tag = tag, external = is_external(url), attr = attr })
        end
      end
    end
  end

  local summary = {}
  local all_links = {}
  for cat, links in pairs(categories) do
    summary[cat] = { count = #links, external = 0, internal = 0 }
    for _, l in ipairs(links) do
      if l.external then summary[cat].external = summary[cat].external + 1
      else summary[cat].internal = summary[cat].internal + 1 end
      table.insert(all_links, l)
    end
  end

  summary.total_links = #all_links
  result.summary = summary
  result.links = all_links
end)

if not ok then
  print('{"status":"error","error":"' .. tostring(err):gsub('"', '\\"'):gsub('\n', '\\n') .. '"}')
  return
end

print(json_encode(result))
