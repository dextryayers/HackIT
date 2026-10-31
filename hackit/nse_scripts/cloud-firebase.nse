local stdnse = require "stdnse"
local http = require "http"
local json = require "json"
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
local msleep = function(ms)
    if stdnse and stdnse.sleep then
        return stdnse.sleep((ms or 0) / 1000)
    end
    if nmap.msleep then
        return nmap.msleep(ms or 0)
    end
    local deadline = nmap.clock() + (ms or 0) / 1000
    while nmap.clock() < deadline do end
    return true
end
local new_socket = nmap.new_socket
local resolve = nmap.resolve

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    if stdnse and stdnse.sleep then
        return stdnse.sleep(seconds)
    end
    if nmap.msleep then
        return nmap.msleep(math.max(0, math.floor((seconds or 0) * 1000)))
    end
    local deadline = nmap.clock() + (seconds or 0)
    while nmap.clock() < deadline do end
    return true
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

description = [[Checks for exposed Firebase Realtime Database or Firestore instances. Attempts to read data, access rules, check authentication configurations, and enumerate common Firebase endpoints without authentication.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "cloud"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and (port.number == 80 or port.number == 443)
end

local firebase_patterns = {
  "firebaseio%.com$", "firestore%.com$", "firebase%.app",
  "firebase%.google%.com", "firebaserules%.googleapis%.com",
  "firestore%.googleapis%.com",
}

local firebase_paths = {
  "/.json", "/.json?shallow=true",
  "/.settings/rules.json", "/.settings.json",
  "/.info.json", "/.stats.json",
  "/.priority.json",
}

local firestore_paths = {
  "/", "/documents", "/documents?pageSize=5",
  "/databases/(default)/documents",
}

action = function(host, port)
  local result = output_table()
  local hostname = host.name or host.ip

  local is_firebase = false
  local firebase_type
  for _, p in ipairs(firebase_patterns) do
    if match(hostname, p) then
      is_firebase = true
      if find(p, "firebaseio") then
        firebase_type = "realtime-database"
      elseif find(p, "firestore") then
        firebase_type = "firestore"
      else
        firebase_type = "firebase"
      end
      break
    end
  end

  if not is_firebase then
    return format_output(false, "Target does not appear to be a Firebase endpoint")
  end

  result.endpoint = hostname
  result.firebase_type = firebase_type

  if firebase_type == "realtime-database" or firebase_type == "firebase" then
    for _, path in ipairs(firebase_paths) do
      local ok, resp = pcall(http.get, hostname, port.number, path, { timeout = 5000 })
      if ok and resp then
        local path_key = gsub(path, "^/", ""):gsub("/", "_"):gsub("%.", "_"):gsub("?", "_")
        if resp.status == 200 then
          if path == "/.json" then
            result.open_database = true
            result.data_accessible = true
            result.data_size = #resp.body
            local ok2, data = pcall(json.parse, resp.body)
            if ok2 then
              result.has_data = data ~= nil
              result.data_keys = data and #data > 0 and #data or nil
            end
          else
            result[path_key .. "_accessible"] = true
            if find(path, "rules") then
              result.rules_accessible = true
            end
          end
        elseif resp.status == 401 then
          result[path_key .. "_unauthorized"] = true
        end
      end
    end
  end

  if firebase_type == "firestore" or firebase_type == "firebase" then
    for _, path in ipairs(firestore_paths) do
      local ok, resp = pcall(http.get, hostname, port.number, path, { timeout = 5000 })
      if ok and resp and resp.status == 200 and resp.body then
        local ok2, data = pcall(json.parse, resp.body)
        if ok2 then
          result.firestore_accessible = true
          if data.documents then
            result.firestore_documents = #data.documents
          end
        end
      end
    end
  end

  return format_output(true, result)
end
