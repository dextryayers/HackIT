-- SEO Scanner
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
  local issues = {}

  local function extract_content(tag, attr)
    local pat = "<" .. tag .. "[^>]*" .. attr .. "%s*=%s*['\"]([^'\"]-)['\"]"
    local _, _, val = body:find(pat)
    if val then return val end
    local pat2 = "<" .. tag .. "[^>]*" .. attr .. "%s*=%s*([^%s>'\"]+)"
    local _, _, val2 = body:find(pat2)
    return val2
  end

  local function between_tags(tag)
    local s, e = body:find("<" .. tag .. "[^>]*>")
    if not s then return nil end
    local _, e2 = body:find("</" .. tag .. ">", e)
    if not e2 then return nil end
    return body:sub(e + 1, e2 - 1)
  end

  -- Title
  local title = between_tags("title")
  if title then
    result.title = { present = true, content = title, length = #title }
    if #title == 0 then table.insert(issues, "Title tag is empty")
    elseif #title < 30 then table.insert(issues, "Title tag too short (" .. #title .. " chars, recommended 30-60)")
    elseif #title > 60 then table.insert(issues, "Title tag too long (" .. #title .. " chars, recommended 30-60)")
    end
    local generic_titles = { "home", "untitled", "page", "new page", "index", "website", "site", "default" }
    for _, t in ipairs(generic_titles) do
      if title:lower():match("^%s*" .. t .. "%s*$") then
        table.insert(issues, "Title is generic/default: '" .. title .. "'")
        break
      end
    end
  else
    result.title = { present = false, content = "", length = 0 }
    table.insert(issues, "Missing <title> tag")
  end

  -- Meta description
  local desc = extract_content("meta", "content")
  local desc_name = extract_content("meta", "name")
  local meta_desc = ""
  local pat_desc = "<meta[^>]-name%s*=%s*['\"]description['\"][^>]-content%s*=%s*['\"]([^'\"]-)['\"]"
  local _, _, md1 = body:find(pat_desc)
  if md1 then
    meta_desc = md1
  else
    local pat_desc2 = "<meta[^>]-content%s*=%s*['\"]([^'\"]-)['\"][^>]-name%s*=%s*['\"]description['\"]"
    local _, _, md2 = body:find(pat_desc2)
    if md2 then meta_desc = md2 end
  end
  result.meta_description = { present = meta_desc ~= "", content = meta_desc, length = #meta_desc }
  if meta_desc == "" then
    table.insert(issues, "Missing meta description")
  elseif #meta_desc < 120 then
    table.insert(issues, "Meta description too short (" .. #meta_desc .. " chars, recommended 120-160)")
  elseif #meta_desc > 160 then
    table.insert(issues, "Meta description too long (" .. #meta_desc .. " chars, recommended 120-160)")
  end

  -- Meta keywords
  local pat_kw = "<meta[^>]-name%s*=%s*['\"]keywords['\"][^>]-content%s*=%s*['\"]([^'\"]-)['\"]"
  local _, _, kw = body:find(pat_kw)
  if not kw then
    local pat_kw2 = "<meta[^>]-content%s*=%s*['\"]([^'\"]-)['\"][^>]-name%s*=%s*['\"]keywords['\"]"
    _, _, kw = body:find(pat_kw2)
  end
  result.meta_keywords = { present = kw ~= nil, content = kw or "" }
  if not kw then table.insert(issues, "Missing meta keywords") end

  -- H1 check
  local h1_count = 0
  local h1_contents = {}
  local h1_pos = 1
  while true do
    local s, e = body:find("<h1[^>]*>", h1_pos)
    if not s then break end
    local _, e2 = body:find("</h1>", e)
    if not e2 then break end
    h1_count = h1_count + 1
    table.insert(h1_contents, body:sub(e + 1, e2 - 1))
    h1_pos = e2 + 1
  end
  result.h1 = { count = h1_count, contents = h1_contents }
  if h1_count == 0 then table.insert(issues, "Missing <h1> tag")
  elseif h1_count > 1 then table.insert(issues, "Multiple <h1> tags found (" .. h1_count .. ")") end

  -- H2-H6 structure
  local found_levels = {}
  for lvl = 2, 6 do
    local pat = "<h" .. lvl .. "[^>]*>"
    local _, e = body:find(pat)
    if e then found_levels[lvl] = true end
  end
  result.heading_structure = {}
  local prev = nil
  for lvl = 2, 6 do
    result.heading_structure["h" .. lvl] = found_levels[lvl] or false
    if found_levels[lvl] then
      if prev and prev < lvl - 1 then
        table.insert(issues, "Heading level skipped: h" .. prev .. " to h" .. lvl)
      end
      prev = lvl
    end
  end

  -- Image alt attributes
  local img_count = 0
  local alt_missing = 0
  local alt_pos = 1
  while true do
    local s, e = body:find("<img[^>]*>", alt_pos)
    if not s then break end
    local tag = body:sub(s, e)
    img_count = img_count + 1
    if not tag:find("alt%s*=") then alt_missing = alt_missing + 1 end
    alt_pos = e + 1
  end
  result.images = { total = img_count, alt_missing = alt_missing }
  if img_count > 0 and alt_missing > 0 then
    table.insert(issues, alt_missing .. " of " .. img_count .. " images missing alt attributes")
  end

  -- Canonical URL
  local pat_can = "<link[^>]-rel%s*=%s*['\"]canonical['\"][^>]-href%s*=%s*['\"]([^'\"]-)['\"]"
  local _, _, can_url = body:find(pat_can)
  if not can_url then
    local pat_can2 = "<link[^>]-href%s*=%s*['\"]([^'\"]-)['\"][^>]-rel%s*=%s*['\"]canonical['\"]"
    _, _, can_url = body:find(pat_can2)
  end
  result.canonical = { present = can_url ~= nil, url = can_url or "" }
  if not can_url then table.insert(issues, "Missing canonical URL") end

  -- Robots meta
  local pat_rob = "<meta[^>]-name%s*=%s*['\"]robots['\"][^>]-content%s*=%s*['\"]([^'\"]-)['\"]"
  local _, _, robots = body:find(pat_rob)
  if not robots then
    local pat_rob2 = "<meta[^>]-content%s*=%s*['\"]([^'\"]-)['\"][^>]-name%s*=%s*['\"]robots['\"]"
    _, _, robots = body:find(pat_rob2)
  end
  result.robots_meta = { present = robots ~= nil, content = robots or "" }

  -- Viewport meta
  local pat_vp = "<meta[^>]-name%s*=%s*['\"]viewport['\"][^>]-content%s*=%s*['\"]([^'\"]-)['\"]"
  local _, _, vp = body:find(pat_vp)
  if not vp then
    local pat_vp2 = "<meta[^>]-content%s*=%s*['\"]([^'\"]-)['\"][^>]-name%s*=%s*['\"]viewport['\"]"
    _, _, vp = body:find(pat_vp2)
  end
  result.viewport_meta = { present = vp ~= nil, content = vp or "" }
  if not vp then table.insert(issues, "Missing viewport meta tag") end

  -- Word count
  local text = body:gsub("<[^>]+>", " "):gsub("%s+", " ")
  local words = 0
  for _ in text:gmatch("%S+") do words = words + 1 end
  result.word_count = words
  if words < 300 then table.insert(issues, "Low word count (" .. words .. " words, recommended 300+)") end

  result.issues_found = issues
  result.issue_count = #issues
end)

if not ok then
  print('{"status":"error","error":"' .. tostring(err):gsub('"', '\\"'):gsub('\n', '\\n') .. '"}')
  return
end

print(json_encode(result))
