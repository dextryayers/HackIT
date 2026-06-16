local stdnse = require "stdnse"

description = [[Checks for default credentials across multiple services using user-provided credential entries.]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "audit"}

local function load_list(arg_names)
  local val = stdnse.get_script_args(arg_names)
  if not val or val == "" then return {} end
  if val:sub(1, 1) == "/" then
    local f, err = io.open(val, "r")
    if f then
      local lines = {}
      for line in f:lines() do
        line = line:gsub("^%s+", ""):gsub("%s+$", "")
        if line ~= "" and line:sub(1, 1) ~= "#" then lines[#lines + 1] = line end
      end
      f:close()
      return lines
    end
  elseif val:find("\n") then
    local lines = {}
    for line in val:gmatch("[^\n]+") do
      line = line:gsub("^%s+", ""):gsub("%s+$", "")
      if line ~= "" and line:sub(1, 1) ~= "#" then lines[#lines + 1] = line end
    end
    return lines
  end
  local items = {}
  for item in val:gmatch("[^,]+") do
    item = item:gsub("^%s+", ""):gsub("%s+$", "")
    if item ~= "" then items[#items + 1] = item end
  end
  return items
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
  local creds_arg = stdnse.get_script_args({"audit-default-credentials.credentials", "credentials"})
  local out = stdnse.output_table()
  out.service = "Default Credentials Check"
  out.target = host.ip
  out.port = port.number

  if not creds_arg or creds_arg == "" then
    out.status = "NO_CREDENTIALS_SPECIFIED"
    out.message = "No credentials specified. Use audit-default-credentials.credentials arg (format: port:user:pass:service:vendor,port:user:pass:...)"
    out.risk = "LOW"
    return out
  end

  local matches = {}
  local entries = load_list({"audit-default-credentials.credentials", "credentials"})
  for _, entry in ipairs(entries) do
    local parts = {}
    for p in entry:gmatch("[^:]+") do
      parts[#parts + 1] = p
    end
    if #parts >= 3 then
      local eport = tonumber(parts[1])
      if eport == port.number then
        matches[#matches + 1] = {
          service = parts[4] or "Unknown",
          vendor = parts[5] or "Generic",
          username = parts[2],
          password = parts[3],
        }
      end
    end
  end

  if #matches > 0 then
    out.status = "DEFAULT_CREDENTIALS_FOUND"
    out.default_credential_patterns = matches
    out.match_count = #matches
    out.risk = "HIGH"
  else
    out.status = "NO_MATCHES"
    out.risk = "LOW"
    out.message = "No matching credential patterns for this port"
  end
  return out
end
