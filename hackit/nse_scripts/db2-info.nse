local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
-- Lua 5.4 has no "bit" module; this is a 32-bit compatible replacement.
local bit = (function()
    local floor = math.floor
    local function toint(x) return floor(x) & 0xFFFFFFFF end
    local function fold(fn, a, ...)
        local r = toint(a)
        for i = 1, select("#", ...) do
            r = toint(fn(r, select(i, ...)))
        end
        return r
    end
    return {
        band = function(...) return fold(function(x, y) return x & y end, ...) end,
        bor = function(...) return fold(function(x, y) return x | y end, ...) end,
        bxor = function(...) return fold(function(x, y) return x ~ y end, ...) end,
        bnot = function(x) return (~toint(x)) & 0xFFFFFFFF end,
        lshift = function(x, n) return (toint(x) << (n & 31)) & 0xFFFFFFFF end,
        rshift = function(x, n) return toint(x) >> (n & 31) end,
        arshift = function(x, n) return toint(x) >> (n & 31) end,
        tobit = function(x) return toint(x) end,
        tohex = function(x) return format("%08x", toint(x)) end,
    }
end)()
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

description = [[Retrieves information from IBM DB2 database instances. Connects to the DB2 TCP service and extracts server version, instance details, platform info, and product release using DRDA protocol probes.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "database"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and (port.number == 50000 or port.number == 50001)
end

local function build_drda_probe()
  local excsat = char(
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
  if match(response, "DB2") or match(response, "DRDA") then
    result.db2_detected = true
    result.protocol = "DRDA"
  end

  local ver_full = match(response, "(%d+%.%d+%.%d+%.%d+)")
    or match(response, "(%d+%.%d+%.%d+)")
  if ver_full then
    result.server_version = ver_full
    local major = match(ver_full, "^(%d+)")
    if major then
      result.version_major = tonumber(major)
    end
  end

  local svrnm = match(response, "SRVNAM[^\x00]*") or match(response, "SRVCLSN[^\x00]*")
  if svrnm then
    result.server_name = gsub(svrnm, "%z", ""):match("=(.+)") or gsub(svrnm, "%z", ""):gsub("^%w+", "")
  end

  local inst = match(response, "INSTNAME[^\x00]*")
  if inst then
    result.instance_name = gsub(inst, "%z", ""):match("=(.+)") or gsub(inst, "%z", ""):gsub("^%w+", "")
  end

  local platform = match(response, "PLATFORM[^\x00]*") or match(response, "PLAT[^\x00]*")
  if platform then
    local pval = gsub(platform, "%z", ""):match("%d+")
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

  local rel = match(response, "REL[^\x00]*") or match(response, "RLS[^\x00]*")
  if rel then
    result.release = gsub(rel, "%z", ""):gsub("^%w+%s*=%s*", "")
  end

  result.response_length = #response

  local security = match(response, "SECMEC[^\x00]*")
  if security then
    result.security_mechanism = gsub(security, "%z", "")
  end

  local codepage = match(response, "CCSID[^\x00]*")
  if codepage then
    result.codepage = gsub(codepage, "%z", ""):match("%d+")
  end
end

action = function(host, port)
  local result = output_table()
  local socket = new_socket()
  socket:set_timeout(5000)

  local ok, err = pcall(socket.connect, socket, host.ip, port.number)
  if not ok then
    return format_output(false, "Failed to connect: " .. tostring(err))
  end

  local probe = build_drda_probe()
  local ok2, send_err = pcall(socket.send, socket, probe)
  if not ok2 then
    socket:close()
    return format_output(false, "Failed to send DRDA probe: " .. tostring(send_err))
  end

  local ok3, response = pcall(socket.receive_buf, socket, 2048, true)
  socket:close()

  if not ok3 or not response or #response < 20 then
    return format_output(false, "No DB2 response received")
  end

  parse_drda_response(response, result)

  if not result.db2_detected then
    return format_output(false, "Target does not appear to be a DB2 instance")
  end

  return format_output(true, result)
end
