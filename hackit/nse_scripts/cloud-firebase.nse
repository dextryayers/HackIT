local stdnse = require "stdnse"
local http = require "http"
local json = require "json"

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
  local result = stdnse.output_table()
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
    return stdnse.format_output(false, "Target does not appear to be a Firebase endpoint")
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

  return stdnse.format_output(true, result)
end
