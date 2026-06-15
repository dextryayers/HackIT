-- Form Scanner
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
  local forms = {}
  local all_input_types = {}
  local total_forms = 0
  local forms_no_csrf = 0
  local has_password = false
  local has_file_upload = false
  local has_payment = false
  local has_email = false
  local insecure_actions = 0

  local pos = 1
  while true do
    local fs, fe = body:find("<form[^>]*>", pos)
    if not fs then break end
    local fe_close, _ = body:find("</form>", fe)
    if not fe_close then break end
    local form_tag = body:sub(fs, fe - 1)
    local form_content = body:sub(fe, fe_close - 1)

    total_forms = total_forms + 1

    local action = ""
    local _, _, act = form_tag:find('action%s*=%s*["\']([^"\']-)[ "\']')
    if act then action = act
    else
      local _, _, act2 = form_tag:find('action%s*=%s*([^%s>]+)')
      if act2 then action = act2 end
    end

    local method = "GET"
    local _, _, meth = form_tag:find('method%s*=%s*["\']([^"\']-)[ "\']')
    if meth then method = meth:upper() end

    if action ~= "" and not action:match("^https://") then
      insecure_actions = insecure_actions + 1
    end

    local inputs = {}
    local has_csrf = false
    local inp_pos = 1
    while true do
      local is, ie = form_content:find("<input[^>]*>", inp_pos)
      if not is then break end
      local inp_tag = form_content:sub(is, ie)
      inp_pos = ie + 1

      local inp_name = ""
      local _, _, nm = inp_tag:find('name%s*=%s*["\']([^"\']-)[ "\']')
      if nm then inp_name = nm end

      local inp_type = "text"
      local _, _, tp = inp_tag:find('type%s*=%s*["\']([^"\']-)[ "\']')
      if tp then inp_type = tp:lower() end

      local inp_value = ""
      local _, _, vl = inp_tag:find('value%s*=%s*["\']([^"\']-)[ "\']')
      if vl then inp_value = vl end

      all_input_types[inp_type] = (all_input_types[inp_type] or 0) + 1

      local entry = { name = inp_name, type = inp_type, value = inp_value }
      table.insert(inputs, entry)

      local name_lower = inp_name:lower()
      if inp_type == "hidden" and (name_lower:find("csrf") or name_lower:find("token") or name_lower == "_token") then
        has_csrf = true
        csrf_token_found = true
      end
      if inp_type == "password" then has_password = true end
      if inp_type == "file" then has_file_upload = true end
      if inp_type == "email" then has_email = true end
      if inp_type == "hidden" and (name_lower:find("card") or name_lower:find("cc_") or name_lower:find("credit") or name_lower:find("payment")) then
        has_payment = true
      end
    end

    if not has_csrf then forms_no_csrf = forms_no_csrf + 1 end

    table.insert(forms, {
      action = action,
      method = method,
      input_count = #inputs,
      has_csrf = has_csrf,
      inputs = inputs
    })

    pos = fe_close + 1
  end

  local input_type_list = {}
  for t, c in pairs(all_input_types) do
    table.insert(input_type_list, { type = t, count = c })
  end

  result.total_forms = total_forms
  result.forms = forms
  result.forms_without_csrf = forms_no_csrf
  result.has_password_fields = has_password
  result.has_file_upload_fields = has_file_upload
  result.has_payment_fields = has_payment
  result.has_email_fields = has_email
  result.insecure_actions = insecure_actions
  result.input_types_found = input_type_list
end)

if not ok then
  print('{"status":"error","error":"' .. tostring(err):gsub('"', '\\"'):gsub('\n', '\\n') .. '"}')
  return
end

print(json_encode(result))
