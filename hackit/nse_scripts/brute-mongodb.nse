local stdnse = require "stdnse"
local nmap = require "nmap"
local openssl = require "openssl"
local os = require "os"
local shortport = require "shortport"



-- nmp function cache
local nmap_register = nmap.register_script
local nmap_settitle = nmap.set_title
local nmap_resolve = nmap.resolve
local nmap_get_port_state = nmap.get_port_state
local nmap_set_port_state = nmap.set_port_state
local comm = nmap.comm
local new_socket = nmap.new_socket
local get_timeout = nmap.get_timeout

-- Performance optimizations
local format = string.format
local lower = string.lower
local upper = string.upper
local byte = string.byte
local sub = string.sub
local match = string.match
local gmatch = string.gmatch
local gsub = string.gsub
local find = string.find
local rep = string.rep
local char = string.char
local concat = table.concat
local insert = table.insert
local remove = table.remove
local sort = table.sort
local move = table.move or function(a1, f, e, t, a2)
    if not a2 then a2 = a1 end
    for i = f, e do a2[t + i - f] = a1[i] end
    return a2
end
local tostring = tostring
local tonumber = tonumber
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local unpack = unpack or table.unpack
local setmetatable = setmetatable
local getmetatable = getmetatable
local error = error
local select = select
local clock = nmap.clock
local msleep = nmap.msleep
local sleep = stdnse.sleep
local strsplit = stdnse.strsplit
local format_output = stdnse.format_output
local output_table = stdnse.output_table

description = [[Attempts to brute-force MongoDB credentials using SCRAM-SHA-1 SASL authentication.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"brute", "intrusive"}

local b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

local function base64_encode(data)
  local result = {}
  for i = 1, #data, 3 do
    local a, b, c = data:byte(i, i + 2)
    local n = (a or 0) * 65536 + (b or 0) * 256 + (c or 0)
    for j = 1, 4 do
      local idx = math.floor(n / (64 ^ (4 - j))) % 64
      insert(result, b64chars:sub(idx + 1, idx + 1))
    end
  end
  local pad = (3 - #data % 3) % 3
  for i = 1, pad do
    result[#result - i + 1] = "="
  end
  return concat(result)
end

local function base64_decode(s)
  s = s:gsub("=+$", "")
  local result = {}
  local buffer = 0
  local bits = 0
  for i = 1, #s do
    local idx = b64chars:find(s:sub(i, i), 1, true)
    if not idx then break end
    idx = idx - 1
    buffer = buffer * 64 + idx
    bits = bits + 6
    if bits >= 8 then
      bits = bits - 8
      insert(result, char(math.floor(buffer / (2 ^ bits)) % 256))
      buffer = buffer % (2 ^ bits)
    end
  end
  return concat(result)
end

local function hex_to_bin(s)
  return (s:gsub("..", function(cc) return char(tonumber(cc, 16)) end))
end

local function load_list(arg_names)
  local val = stdnse.get_script_args(arg_names)
  if not val or val == "" then return {} end
  if val:byte() == 47 then
    local f, err = io.open(val, "r")
    if f then
      local lines = {}
      for line in f:lines() do
        line = line:gsub("^%s+", ""):gsub("%s+$", "")
        if line ~= "" and line:byte() ~= 35 then insert(lines, line end)
      end
      f:close()
      return lines
    end
  elseif val:find("\n") then
    local lines = {}
    for line in val:gmatch("[^\n]+") do
      line = line:gsub("^%s+", ""):gsub("%s+$", "")
      if line ~= "" and line:byte() ~= 35 then insert(lines, line end)
    end
    return lines
  end
  local items = {}
  for item in val:gmatch("[^,]+") do
    item = item:gsub("^%s+", ""):gsub("%s+$", "")
    if item ~= "" then insert(items, item) end
  end
  return items
end

local function le32(n)
  return char(n % 256, math.floor(n / 256) % 256, math.floor(n / 65536) % 256, math.floor(n / 16777216) % 256)
end

local function xor_bytes(a, b)
  local len = math.min(#a, #b)
  local res = {}
  for i = 1, len do
    res[i] = char(byte(a, i) ~ byte(b, i))
  end
  return concat(res)
end

local function hmac_sha1_raw(key, data)
  local h = openssl.hmac("sha1", key, data)
  if #h == 20 then return h end
  return hex_to_bin(h:lower())
end

local function pbkdf2_hmac_sha1(password, salt, iterations, dkLen)
  local function int_be(n)
    return char(
      math.floor(n / 16777216) % 256, math.floor(n / 65536) % 256,
      math.floor(n / 256) % 256, n % 256)
  end
  local blocks = math.ceil(dkLen / 20)
  local result = {}
  for b = 1, blocks do
    local u = hmac_sha1_raw(password, salt .. int_be(b))
    local t = u
    for i = 2, iterations do
      u = hmac_sha1_raw(password, u)
      t = xor_bytes(t, u)
    end
    result[b] = t
  end
  return concat(result):sub(1, dkLen)
end

local function bson_enc_str(val)
  local d = val .. char(0)
  return le32(#d) .. d
end

local function bson_doc(elems)
  local body = concat(elems)
  return le32(4 + #body + 1) .. body .. char(0)
end

local function bson_elem_int(name, val)
  return char(0x10) .. name .. char(0) .. le32(val)
end

local function bson_elem_str(name, val)
  return char(0x02) .. name .. char(0) .. bson_enc_str(val)
end

local function bson_elem_bool(name, val)
  return char(0x08) .. name .. char(0) .. char(val and 1 or 0)
end

local function bson_get_val(doc, key)
  local pos = 5
  local doc_len = #doc
  while pos < doc_len do
    local etype = doc:byte(pos)
    if not etype then break end
    pos = pos + 1
    local n = ""
    while pos <= doc_len do
      local b = doc:byte(pos)
      if b == 0 then pos = pos + 1; break end
      n = n .. char(b)
      pos = pos + 1
    end
    if n == key then
      if etype == 0x02 then
        local sl = byte(doc, pos) + byte(doc, pos + 1) * 256 + byte(doc, pos + 2) * 65536 + byte(doc, pos + 3) * 16777216
        return doc:sub(pos + 4, pos + sl - 2)
      elseif etype == 0x10 then
        return byte(doc, pos) + byte(doc, pos + 1) * 256 + byte(doc, pos + 2) * 65536 + byte(doc, pos + 3) * 16777216
      elseif etype == 0x08 then
        return doc:byte(pos) == 1
      elseif etype == 0x03 then
        local sl = byte(doc, pos) + byte(doc, pos + 1) * 256 + byte(doc, pos + 2) * 65536 + byte(doc, pos + 3) * 16777216
        return doc:sub(pos + 4, pos + sl - 2)
      end
      return nil
    end
    if etype == 0x10 then pos = pos + 4
    elseif etype == 0x01 then pos = pos + 8
    elseif etype == 0x02 or etype == 0x03 or etype == 0x04 then
      local sl = byte(doc, pos) + byte(doc, pos + 1) * 256 + byte(doc, pos + 2) * 65536 + byte(doc, pos + 3) * 16777216
      pos = pos + sl
    elseif etype == 0x05 then
      local bl = byte(doc, pos) + byte(doc, pos + 1) * 256 + byte(doc, pos + 2) * 65536 + byte(doc, pos + 3) * 16777216
      pos = pos + 5 + bl
    elseif etype == 0x07 then pos = pos + 12
    elseif etype == 0x08 then pos = pos + 1
    elseif etype == 0x12 then pos = pos + 8
    elseif etype == 0x0A then
    else pos = pos + 1
    end
  end
  return nil
end

local function mongo_query(coll, query)
  local body = char(0, 0, 0, 0) .. coll .. char(0) .. char(0, 0, 0, 0) .. char(255, 255, 255, 255) .. query
  return le32(16 + #body) .. le32(1) .. le32(0) .. le32(2004) .. body
end

local function mongo_recv(socket)
  local hdr = socket:receive_bytes(4)
  if not hdr or #hdr < 4 then return nil end
  local len = byte(hdr, 1) + byte(hdr, 2) * 256 + byte(hdr, 3) * 65536 + byte(hdr, 4) * 16777216
  if len < 4 then return nil end
  local rest = socket:receive_bytes(len - 4)
  if not rest then return nil end
  local data = hdr .. rest
  if #data < 36 then return nil end
  local num = byte(data, 29) + byte(data, 30) * 256 + byte(data, 31) * 65536 + byte(data, 32) * 16777216
  if num == 0 or #data < 37 then return nil end
  return data:sub(37)
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.number == 27017 end

action = function(host, port)
  local users = load_list({"brute-mongodb.users", "users"})
  local passes = load_list({"brute-mongodb.passwords", "passwords"})
  local delay = tonumber(stdnse.get_script_args({"brute-mongodb.delay", "delay"}) or 100)
  local max_attempts = tonumber(stdnse.get_script_args({"brute-mongodb.max_attempts", "max_attempts"}) or 1000)
  local timeout = tonumber(stdnse.get_script_args({"brute-mongodb.timeout", "timeout"}) or 10)
  local stop_on_first = stdnse.get_script_args({"brute-mongodb.stop_on_first", "stop_on_first"})
  if stop_on_first == nil or stop_on_first == "" then stop_on_first = true
  else stop_on_first = (stop_on_first:lower() == "true" or stop_on_first == "1") end

  if #users == 0 or #passes == 0 then
    return format_output(false, "No credentials provided. Use brute-mongodb.users and brute-mongodb.passwords script args")
  end

  local start_time = os.time()
  local found = {}
  local attempts = 0
  local errors = 0
  local success_count = 0
  local stop = false

  for _, u in ipairs(users) do
    if stop then break end
    for _, p in ipairs(passes) do
      if stop or attempts >= max_attempts then break end
      local socket = new_socket()
      socket:set_timeout(timeout * 1000)
      local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then errors = errors + 1; return false end

        local nonce = format("%.0f", os.time() * 1000000)
        local nonce_b64 = base64_encode(nonce)
        local client_first_bare = "n=" .. u .. ",r=" .. nonce_b64
        local client_first_msg = "n,," .. client_first_bare

        local sasl_start_doc = bson_doc({
          bson_elem_int("saslStart", 1),
          bson_elem_str("mechanism", "SCRAM-SHA-1"),
          bson_elem_str("payload", base64_encode(client_first_msg)),
          bson_elem_bool("autoAuthorize", 1),
          bson_elem_str("$db", "admin"),
        })
        socket:send(mongo_query("admin.$cmd", sasl_start_doc))
        local resp_doc = mongo_recv(socket)
        if not resp_doc then socket:close(); return false end

        local ok_val = bson_get_val(resp_doc, "ok")
        if not ok_val or (type(ok_val) ~= "number") then
          socket:close(); return false
        end
        local conv_id = bson_get_val(resp_doc, "conversationId")
        local payload_b64 = bson_get_val(resp_doc, "payload")
        if not payload_b64 then socket:close(); return false end

        local server_first = base64_decode(payload_b64)
        local r_nonce = server_first:match("r=([^,]+)")
        local salt_b64 = server_first:match("s=([^,]+)")
        local iterations = tonumber(server_first:match("i=([^,]+)"))
        if not r_nonce or not salt_b64 or not iterations then
          socket:close(); return false
        end

        local salt_raw = base64_decode(salt_b64)
        local salted_pass = pbkdf2_hmac_sha1(p, salt_raw, iterations, 20)
        local client_key = hmac_sha1_raw(salted_pass, "Client Key")
        local stored_key_hex = openssl.sha1(client_key)
        local stored_key = hex_to_bin(stored_key_hex:lower())

        local client_final_wo = "c=biws,r=" .. r_nonce
        local auth_msg = client_first_bare .. "," .. server_first .. "," .. client_final_wo
        local client_sig = hmac_sha1_raw(stored_key, auth_msg)
        local client_proof = xor_bytes(client_key, client_sig)
        local client_final = client_final_wo .. ",p=" .. base64_encode(client_proof)

        local sasl_cont_doc = bson_doc({
          bson_elem_int("saslContinue", 1),
          bson_elem_int("conversationId", conv_id),
          bson_elem_str("payload", base64_encode(client_final)),
          bson_elem_str("$db", "admin"),
        })
        socket:send(mongo_query("admin.$cmd", sasl_cont_doc))
        local cont_resp = mongo_recv(socket)
        socket:close()

        if not cont_resp then return false end
        local ok2 = bson_get_val(cont_resp, "ok")
        if not ok2 then return false end
        local done = bson_get_val(cont_resp, "done")
        return done == true
      end)
      if not ok then
        pcall(socket.close, socket)
        errors = errors + 1
      elseif result then
        success_count = success_count + 1
        insert(found, {user = u, password = p})
        if stop_on_first then stop = true end
      end
      attempts = attempts + 1
      if delay > 0 and not stop then sleep(delay / 1000) end
    end
  end

  local elapsed = os.time() - start_time
  local out = output_table()
  out.service = "MongoDB"
  out.port = port.number
  out.attempts = attempts
  out.success_count = success_count
  out.time_taken = elapsed .. "s"
  if #found > 0 then
    out.status = "VULNERABLE"
    out.found_credentials = found
  else
    out.status = "SECURE"
  end
  if errors > 0 then out.errors = errors end
  return out
end
