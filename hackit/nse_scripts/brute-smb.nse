local stdnse = require "stdnse"
local nmap = require "nmap"
local openssl = require "openssl"
local os = require "os"
local bit = require "bit"
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

description = [[Attempts to brute-force SMB credentials using NTLMSSP authentication.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"brute", "intrusive"}

local function load_list(arg_names)
  local val = stdnse.get_script_args(arg_names)
  if not val or val == "" then return {} end
  if byte(val) == 47 then
    local f, err = io.open(val, "r")
    if f then
      local lines = {}
      for line in f:lines() do
        line = gsub(line, "^%s+", ""):gsub("%s+$", "")
        if line ~= "" and byte(line) ~= 35 then insert(lines, line) end
      end
      f:close()
      return lines
    end
  elseif find(val, "\n") then
    local lines = {}
    for line in gmatch(val, "[^\n]+") do
      line = gsub(line, "^%s+", ""):gsub("%s+$", "")
      if line ~= "" and byte(line) ~= 35 then insert(lines, line) end
    end
    return lines
  end
  local items = {}
  for item in gmatch(val, "[^,]+") do
    item = gsub(item, "^%s+", ""):gsub("%s+$", "")
    if item ~= "" then insert(items, item) end
  end
  return items
end

local function le16(n) return char(n % 256, math.floor(n / 256) % 256) end
local function le32(n)
  return char(n % 256, math.floor(n / 256) % 256, math.floor(n / 65536) % 256, math.floor(n / 16777216) % 256)
end

local function utf16le(s)
  local res = {}
  for i = 1, #s do insert(res, char(byte(s, i), 0)) end
  return concat(res)
end

local function lrot(x, n)
  return bit.bor(bit.lshift(x, n), bit.rshift(x, 32 - n))
end

local function md4(message)
  local len = #message
  local bits = len * 8
  local padded = message .. "\x80"
  while (#padded % 64) ~= 56 do
    padded = padded .. "\x00"
  end
  padded = padded .. char(bits % 256, math.floor(bits / 256) % 256,
    math.floor(bits / 65536) % 256, math.floor(bits / 16777216) % 256, 0, 0, 0, 0)

  local a, b, c, d = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
  local function F(x, y, z) return bit.bor(bit.band(x, y), bit.band(bit.bnot(x), z)) end
  local function G(x, y, z) return bit.bor(bit.band(x, y), bit.band(x, z), bit.band(y, z)) end
  local function H(x, y, z) return bit.bxor(x, bit.bxor(y, z)) end

  for i = 1, #padded, 64 do
    local block = sub(padded, i, i + 63)
    local X = {}
    for j = 0, 15 do
      local o = j * 4 + 1
      X[j] = byte(block, o) + byte(block, o + 1) * 256
        + byte(block, o + 2) * 65536 + byte(block, o + 3) * 16777216
    end
    local aa, bb, cc, dd = a, b, c, d
    local function r1(va, vb, vc, vd, k, s) return lrot(bit.band(va + F(vb, vc, vd) + X[k], 0xFFFFFFFF), s) end
    local function r2(va, vb, vc, vd, k, s) return lrot(bit.band(va + G(vb, vc, vd) + X[k] + 0x5A827999, 0xFFFFFFFF), s) end
    local function r3(va, vb, vc, vd, k, s) return lrot(bit.band(va + H(vb, vc, vd) + X[k] + 0x6ED9EBA1, 0xFFFFFFFF), s) end

    a = r1(a, b, c, d, 0, 3); d = r1(d, a, b, c, 1, 7); c = r1(c, d, a, b, 2, 11); b = r1(b, c, d, a, 3, 19)
    a = r1(a, b, c, d, 4, 3); d = r1(d, a, b, c, 5, 7); c = r1(c, d, a, b, 6, 11); b = r1(b, c, d, a, 7, 19)
    a = r1(a, b, c, d, 8, 3); d = r1(d, a, b, c, 9, 7); c = r1(c, d, a, b, 10, 11); b = r1(b, c, d, a, 11, 19)
    a = r1(a, b, c, d, 12, 3); d = r1(d, a, b, c, 13, 7); c = r1(c, d, a, b, 14, 11); b = r1(b, c, d, a, 15, 19)
    a = r2(a, b, c, d, 0, 3); d = r2(d, a, b, c, 4, 5); c = r2(c, d, a, b, 8, 9); b = r2(b, c, d, a, 12, 13)
    a = r2(a, b, c, d, 1, 3); d = r2(d, a, b, c, 5, 5); c = r2(c, d, a, b, 9, 9); b = r2(b, c, d, a, 13, 13)
    a = r2(a, b, c, d, 2, 3); d = r2(d, a, b, c, 6, 5); c = r2(c, d, a, b, 10, 9); b = r2(b, c, d, a, 14, 13)
    a = r2(a, b, c, d, 3, 3); d = r2(d, a, b, c, 7, 5); c = r2(c, d, a, b, 11, 9); b = r2(b, c, d, a, 15, 13)
    a = r3(a, b, c, d, 0, 3); d = r3(d, a, b, c, 8, 9); c = r3(c, d, a, b, 4, 11); b = r3(b, c, d, a, 12, 15)
    a = r3(a, b, c, d, 2, 3); d = r3(d, a, b, c, 10, 9); c = r3(c, d, a, b, 6, 11); b = r3(b, c, d, a, 14, 15)
    a = r3(a, b, c, d, 1, 3); d = r3(d, a, b, c, 9, 9); c = r3(c, d, a, b, 5, 11); b = r3(b, c, d, a, 13, 15)
    a = r3(a, b, c, d, 3, 3); d = r3(d, a, b, c, 11, 9); c = r3(c, d, a, b, 7, 11); b = r3(b, c, d, a, 15, 15)
    a = bit.band(a + aa, 0xFFFFFFFF); b = bit.band(b + bb, 0xFFFFFFFF)
    c = bit.band(c + cc, 0xFFFFFFFF); d = bit.band(d + dd, 0xFFFFFFFF)
  end
  return char(a % 256, math.floor(a / 256) % 256, math.floor(a / 65536) % 256, math.floor(a / 16777216) % 256,
    b % 256, math.floor(b / 256) % 256, math.floor(b / 65536) % 256, math.floor(b / 16777216) % 256,
    c % 256, math.floor(c / 256) % 256, math.floor(c / 65536) % 256, math.floor(c / 16777216) % 256,
    d % 256, math.floor(d / 256) % 256, math.floor(d / 65536) % 256, math.floor(d / 16777216) % 256)
end

local function hmac_md5_raw(key, data)
  local h = openssl.hmac("md5", key, data)
  if #h == 16 then return h end
  return (gsub(h, "..", function(cc) return char(tonumber(cc, 16)) end))
end

local function ntlm_hash(password)
  return md4(utf16le(password))
end

local function ntlmv2_response(nt_hash, server_challenge, user, domain)
  local client_challenge = le32(os.time()) .. rep(char(0x00), 4)
  local timestamp_data = char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

  local blob = char(0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    .. timestamp_data .. client_challenge
    .. char(0x00, 0x00, 0x00, 0x00)
    .. rep(char(0x00), 4)

  local nt_proof = hmac_md5_raw(nt_hash, server_challenge .. blob)
  local nt_resp = nt_proof .. blob

  local lm_proof = hmac_md5_raw(nt_hash, server_challenge .. client_challenge)
  local lm_resp = lm_proof .. client_challenge

  local domain_uni = utf16le(domain)
  local user_uni = utf16le(user)
  local target_uni = ""
  local session_key = rep(char(0x00), 16)

  local hdr_size = 64
  local off = hdr_size
  local lm_off, lm_len = off, #lm_resp; off = off + lm_len
  local nt_off, nt_len = off, #nt_resp; off = off + nt_len
  local dom_off, dom_len = off, #domain_uni; off = off + dom_len
  local usr_off, usr_len = off, #user_uni; off = off + usr_len
  local tgt_off, tgt_len = off, #target_uni; off = off + tgt_len
  local ses_off, ses_len = off, 16; off = off + ses_len

  local msg = "NTLMSSP\x00" .. char(0x03)
    .. le16(lm_len) .. le16(lm_len) .. le32(lm_off)
    .. le16(nt_len) .. le16(nt_len) .. le32(nt_off)
    .. le16(dom_len) .. le16(dom_len) .. le32(dom_off)
    .. le16(usr_len) .. le16(usr_len) .. le32(usr_off)
    .. le16(tgt_len) .. le16(tgt_len) .. le32(tgt_off)
    .. le16(ses_len) .. le16(ses_len) .. le32(ses_off)
    .. le32(0x00000001)
    .. lm_resp .. nt_resp .. domain_uni .. user_uni .. target_uni .. session_key

  return msg
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 139 or port.number == 445) end

action = function(host, port)
  local users = load_list({"brute-smb.users", "users"})
  local passes = load_list({"brute-smb.passwords", "passwords"})
  local delay = tonumber(stdnse.get_script_args({"brute-smb.delay", "delay"}) or 100)
  local max_attempts = tonumber(stdnse.get_script_args({"brute-smb.max_attempts", "max_attempts"}) or 1000)
  local timeout = tonumber(stdnse.get_script_args({"brute-smb.timeout", "timeout"}) or 10)
  local stop_on_first = stdnse.get_script_args({"brute-smb.stop_on_first", "stop_on_first"})
  if stop_on_first == nil or stop_on_first == "" then stop_on_first = true
  else stop_on_first = (lower(stop_on_first) == "true" or stop_on_first == "1") end

  if #users == 0 or #passes == 0 then
    return format_output(false, "No credentials provided. Use brute-smb.users and brute-smb.passwords script args")
  end

  local start_time = os.time()
  local found = {}
  local attempts = 0
  local errors = 0
  local success_count = 0
  local stop = false

  local function build_session_setup(user, pass, domain, challenge)
    local nt_hash = ntlm_hash(pass)
    local ntlmssp = ntlmv2_response(nt_hash, challenge, user, domain)
    local sec_blob_len = #ntlmssp

    local smb_hdr = "\xffSMB"
      .. char(0x73) -- SMB_COM_SESSION_SETUP_ANDX
      .. char(0x00, 0x00, 0x00, 0x00) -- status
      .. char(0x18) -- flags
      .. char(0x01, 0x20) -- flags2
      .. char(0x00, 0x00) -- pid high
      .. rep(char(0x00), 8) -- signature
      .. char(0x00, 0x00) -- reserved
      .. char(0x00, 0x00) -- tid
      .. char(0x00, 0x00) -- pid low
      .. char(0x00, 0x00) -- uid
      .. char(0x00, 0x00) -- mid

    local andx_offset = 4 + 32 + 2 + 2 + 2 + sec_blob_len

    local body = char(0x0c) -- word count (12)
      .. char(0xff) -- no andx
      .. char(0x00, 0x00) -- reserved
      .. le16(andx_offset) -- andx offset
      .. le16(65535) -- max buffer size
      .. le16(2) -- max mpx count
      .. le16(1) -- vc number
      .. le32(0) -- session key
      .. le16(sec_blob_len) -- security blob length
      .. le32(0) -- reserved
      .. le16(sec_blob_len) .. ntlmssp -- security blob

    local pkt = smb_hdr .. body
    local len = #pkt
    return char(0x00, math.floor(len / 65536) % 256, math.floor(len / 256) % 256, len % 256) .. pkt
  end

  for _, u in ipairs(users) do
    if stop then break end
    for _, p in ipairs(passes) do
      if stop or attempts >= max_attempts then break end
      local socket = new_socket()
      socket:set_timeout(timeout * 1000)
      local ok, result = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then errors = errors + 1; return false end

        local neg_pkt = char(0x00, 0x00, 0x00, 0x24)
          .. "\xffSMB" .. char(0x72)
          .. char(0x00, 0x00, 0x00, 0x00)
          .. char(0x18)
          .. char(0x01, 0x20)
          .. char(0x00, 0x00)
          .. rep(char(0x00), 8)
          .. char(0x00, 0x00)
          .. char(0x00, 0x00)
          .. char(0x00, 0x00)
          .. char(0x00, 0x00)
          .. char(0x00, 0x00)
          .. char(0x00) -- word count
          .. char(0x00, 0x00) -- byte count
        socket:send(neg_pkt)

        local neg_resp = socket:receive_bytes(256)
        if not neg_resp then socket:close(); return false end

        local ss = find(neg_resp, "\xffSMB")
        if not ss then socket:close(); return false end
        local smb = sub(neg_resp, ss)

        local chal_pos = find(smb, "NTLMSSP")
        if not chal_pos then socket:close(); return false end
        local challenge = sub(smb, chal_pos + 24, chal_pos + 31)
        if #challenge < 8 then socket:close(); return false end

        socket:send(build_session_setup(u, p, "WORKGROUP", challenge))
        local ses_resp = socket:receive_bytes(128)
        socket:close()

        if ses_resp then
          local ss2 = find(ses_resp, "\xffSMB")
          if ss2 then
            local hdr = sub(ses_resp, ss2, ss2 + 31)
            if #hdr >= 9 then
              local status_code = byte(hdr, 6) + byte(hdr, 7) * 256
                + byte(hdr, 8) * 65536 + byte(hdr, 9) * 16777216
              if status_code == 0 then return true end
            end
          end
        end
        return false
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
  out.service = "SMB"
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
