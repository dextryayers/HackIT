local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
local bit = require "bit"

description = [[Retrieves information from IBM DB2 database instances. Connects to the DB2 TCP service and extracts server version, instance details, platform info, and product release using DRDA protocol probes.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "database"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and (port.number == 50000 or port.number == 50001)
end

local function build_drda_probe()
  local excsat = string.char(
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  )
  return excsat
end

local function parse_drda_response(response, result)
  if response:match("DB2") or response:match("DRDA") then
    result.db2_detected = true
    result.protocol = "DRDA"
  end

  local ver_full = response:match("(%d+%.%d+%.%d+%.%d+)")
    or response:match("(%d+%.%d+%.%d+)")
  if ver_full then
    result.server_version = ver_full
    local major = ver_full:match("^(%d+)")
    if major then
      result.version_major = tonumber(major)
    end
  end

  local svrnm = response:match("SRVNAM[^\x00]*") or response:match("SRVCLSN[^\x00]*")
  if svrnm then
    result.server_name = svrnm:gsub("%z", ""):match("=(.+)") or svrnm:gsub("%z", ""):gsub("^%w+", "")
  end

  local inst = response:match("INSTNAME[^\x00]*")
  if inst then
    result.instance_name = inst:gsub("%z", ""):match("=(.+)") or inst:gsub("%z", ""):gsub("^%w+", "")
  end

  local platform = response:match("PLATFORM[^\x00]*") or response:match("PLAT[^\x00]*")
  if platform then
    local pval = platform:gsub("%z", ""):match("%d+")
    local platforms = {
      ["0"] = "Unknown",
      ["1"] = "OS/2",
      ["2"] = "DOS",
      ["3"] = "AIX",
      ["4"] = "Windows NT/2000/XP",
      ["5"] = "Windows 9x",
      ["6"] = "Windows 3.x",
      ["7"] = "Sun Solaris",
      ["8"] = "HP-UX",
      ["9"] = "MacOS",
      ["10"] = "Linux",
      ["11"] = "AS/400",
      ["12"] = "OS/390",
      ["13"] = "VM/ESA",
      ["14"] = "MVS/ESA",
      ["15"] = "z/OS",
    }
    result.platform = platforms[pval] or pval
  end

  local rel = response:match("REL[^\x00]*") or response:match("RLS[^\x00]*")
  if rel then
    result.release = rel:gsub("%z", ""):gsub("^%w+%s*=%s*", "")
  end

  result.response_length = #response

  local security = response:match("SECMEC[^\x00]*")
  if security then
    result.security_mechanism = security:gsub("%z", "")
  end

  local codepage = response:match("CCSID[^\x00]*")
  if codepage then
    result.codepage = codepage:gsub("%z", ""):match("%d+")
  end
end

action = function(host, port)
  local result = stdnse.output_table()
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local ok, err = pcall(socket.connect, socket, host.ip, port.number)
  if not ok then
    return stdnse.format_output(false, "Failed to connect: " .. tostring(err))
  end

  local probe = build_drda_probe()
  local ok2, send_err = pcall(socket.send, socket, probe)
  if not ok2 then
    socket:close()
    return stdnse.format_output(false, "Failed to send DRDA probe: " .. tostring(send_err))
  end

  local ok3, response = pcall(socket.receive_buf, socket, 2048, true)
  socket:close()

  if not ok3 or not response or #response < 20 then
    return stdnse.format_output(false, "No DB2 response received")
  end

  parse_drda_response(response, result)

  if not result.db2_detected then
    return stdnse.format_output(false, "Target does not appear to be a DB2 instance")
  end

  return stdnse.format_output(true, result)
end
