-- Meta Extractor
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

local function extract_meta_attr(tag, attr)
  local patterns = {
    ' ' .. attr .. '="([^"]-)"',
    " " .. attr .. "='([^']-)'",
  }
  for _, pat in ipairs(patterns) do
    local _, _, val = tag:find(pat)
    if val then return val end
  end
  return ""
end

local result = { status = "ok" }
local ok, err = pcall(function()
  -- Standard meta tags
  local meta_tags = {}
  local pos = 1
  while true do
    local s, e = body:find("<meta[^>]*>", pos)
    if not s then break end
    local tag = body:sub(s, e)
    pos = e + 1
    local name = extract_meta_attr(tag, "name")
    local content = extract_meta_attr(tag, "content")
    local property = extract_meta_attr(tag, "property")
    local charset = extract_meta_attr(tag, "charset")
    local http_equiv = extract_meta_attr(tag, "http-equiv")
    if name ~= "" or content ~= "" or property ~= "" or charset ~= "" or http_equiv ~= "" then
      table.insert(meta_tags, {
        name = name,
        content = content,
        property = property,
        charset = charset,
        http_equiv = http_equiv
      })
    end
  end
  result.meta_tags = meta_tags

  -- OpenGraph
  local og_tags = {}
  local og_pos = 1
  while true do
    local s, e = body:find("<meta[^>]-property%s*=%s*[\"']og:([^\"']-)[\"'][^>]*>", og_pos)
    if not s then
      local s2, e2 = body:find("<meta[^>]-name%s*=%s*[\"']og:([^\"']-)[\"'][^>]*>", og_pos)
      if not s2 then break end
      local _, _, og_name = body:find("<meta[^>]-name%s*=%s*[\"']og:([^\"']-)[\"'][^>]*>", og_pos)
      local _, _, og_cont = body:find("<meta[^>]-name%s*=%s*[\"']og:[^\"']-[\"'][^>]-content%s*=%s*[\"']([^\"']-)[\"']", og_pos)
      if not og_cont then
        local _, _, og_cont2 = body:find("<meta[^>]-content%s*=%s*[\"']([^\"']-)[\"'][^>]-name%s*=%s*[\"']og:([^\"']-)[\"']", og_pos)
        if og_cont2 then og_cont = og_cont2 end
      end
      if og_name then
        table.insert(og_tags, { property = "og:" .. og_name, content = og_cont or "" })
      end
      og_pos = s2 + 1
    else
      local _, _, og_name2 = body:find("<meta[^>]-property%s*=%s*[\"']og:([^\"']-)[\"'][^>]-content%s*=%s*[\"']([^\"']-)[\"']", og_pos)
      if not og_name2 then
        local _, _, og_name3, og_cont3 = body:find("<meta[^>]-content%s*=%s*[\"']([^\"']-)[\"'][^>]-property%s*=%s*[\"']og:([^\"']-)[\"']", og_pos)
        if og_name3 then
          table.insert(og_tags, { property = "og:" .. og_cont3, content = og_name3 })
        end
      else
        local _, _, og_name2v, og_cont2v = body:find("<meta[^>]-property%s*=%s*[\"']og:([^\"']-)[\"'][^>]-content%s*=%s*[\"']([^\"']-)[\"']", og_pos)
        if og_name2v then
          table.insert(og_tags, { property = "og:" .. og_name2v, content = og_cont2v })
        end
      end
      og_pos = s + 1
    end
  end
  -- Simpler OG extraction
  if #og_tags == 0 then
    local og_pos2 = 1
    while true do
      local s, e = body:find("<meta[^>]*>", og_pos2)
      if not s then break end
      local tag = body:sub(s, e)
      og_pos2 = e + 1
      local prop = extract_meta_attr(tag, "property")
      local cont = extract_meta_attr(tag, "content")
      if prop:find("^og:") then
        table.insert(og_tags, { property = prop, content = cont })
      end
    end
  end
  result.opengraph = og_tags

  -- Twitter Card
  local twitter_tags = {}
  local tw_pos = 1
  while true do
    local s, e = body:find("<meta[^>]*>", tw_pos)
    if not s then break end
    local tag = body:sub(s, e)
    tw_pos = e + 1
    local name = extract_meta_attr(tag, "name")
    local cont = extract_meta_attr(tag, "content")
    if name:find("^twitter:") then
      table.insert(twitter_tags, { name = name, content = cont })
    end
  end
  result.twitter_cards = twitter_tags

  -- JSON-LD
  local jsonld = {}
  local jl_pos = 1
  while true do
    local s, e = body:find('<script[^>]-type%s*=%s*["\']application/ld+json["\'][^>]*>', jl_pos)
    if not s then break end
    local _, e2 = body:find('</script>', e)
    if not e2 then break end
    local raw = body:sub(e + 1, e2 - 1)
    table.insert(jsonld, raw)
    jl_pos = e2 + 1
  end
  result.json_ld = jsonld

  -- Microdata
  local microdata = { items = {} }
  local md_pos = 1
  while true do
    local s, e = body:find("itemscope", md_pos)
    if not s then break end
    local tag_start = body:sub(1, s):find("[^>]*$")
    local open_pos = s
    for i = s, 1, -1 do
      if body:sub(i,i) == "<" then open_pos = i; break end
    end
    local tag = body:sub(open_pos, s + 8)
    local itemtype = extract_meta_attr(tag, "itemtype")
    local itemprop = extract_meta_attr(tag, "itemprop")
    if itemtype ~= "" or itemprop ~= "" then
      table.insert(microdata.items, { itemtype = itemtype, itemprop = itemprop })
    end
    md_pos = e + 1
  end
  result.microdata = microdata

  -- Favicon
  local favicons = {}
  local fv_pos = 1
  while true do
    local s, e = body:find("<link[^>]*>", fv_pos)
    if not s then break end
    local tag = body:sub(s, e)
    fv_pos = e + 1
    local rel = extract_meta_attr(tag, "rel"):lower()
    local href = extract_meta_attr(tag, "href")
    if rel:find("icon") or rel:find("apple%-touch%-icon") or rel:find("shortcut icon") then
      table.insert(favicons, { rel = rel, href = href })
    end
  end
  result.favicons = favicons

  -- RSS/Atom feeds
  local feeds = {}
  local fd_pos = 1
  while true do
    local s, e = body:find("<link[^>]*>", fd_pos)
    if not s then break end
    local tag = body:sub(s, e)
    fd_pos = e + 1
    local rel = extract_meta_attr(tag, "rel"):lower()
    local href = extract_meta_attr(tag, "href")
    local type_attr = extract_meta_attr(tag, "type"):lower()
    local title = extract_meta_attr(tag, "title")
    if rel == "alternate" and (type_attr:find("rss") or type_attr:find("atom") or type_attr:find("xml")) then
      table.insert(feeds, { rel = rel, href = href, type = type_attr, title = title })
    end
  end
  result.feeds = feeds

  -- Resource hints (dns-prefetch, preconnect, preload, prefetch)
  local hints = {}
  local hn_pos = 1
  while true do
    local s, e = body:find("<link[^>]*>", hn_pos)
    if not s then break end
    local tag = body:sub(s, e)
    hn_pos = e + 1
    local rel = extract_meta_attr(tag, "rel"):lower()
    local href = extract_meta_attr(tag, "href")
    local as = extract_meta_attr(tag, "as")
    local hint_types = { ["dns-prefetch"] = true, preconnect = true, preload = true, prefetch = true }
    if hint_types[rel] then
      table.insert(hints, { rel = rel, href = href, as = as })
    end
  end
  result.resource_hints = hints
end)

if not ok then
  print('{"status":"error","error":"' .. tostring(err):gsub('"', '\\"'):gsub('\n', '\\n') .. '"}')
  return
end

print(json_encode(result))
