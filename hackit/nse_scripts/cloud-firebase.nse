local stdnse = require "stdnse"
local http = require "http"
local json = require "json"
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
    if hostname:match(p) then
      is_firebase = true
      if p:find("firebaseio") then
        firebase_type = "realtime-database"
      elseif p:find("firestore") then
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
        local path_key = path:gsub("^/", ""):gsub("/", "_"):gsub("%.", "_"):gsub("?", "_")
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
            if path:find("rules") then
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
