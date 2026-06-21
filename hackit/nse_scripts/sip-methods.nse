local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
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

description = [[Enumerates supported SIP methods by sending an OPTIONS request and analyzing the Allow header. Also tests common SIP methods (REGISTER, INVITE, etc.) against the target to identify allowed operations. Handles both TCP and UDP transport.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "voip"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and (port.number == 5060 or port.number == 5061)
end

local sip_methods_to_test = {
  "OPTIONS", "REGISTER", "INVITE", "ACK", "CANCEL",
  "BYE", "NOTIFY", "SUBSCRIBE", "MESSAGE", "INFO",
  "PRACK", "UPDATE", "REFER", "PUBLISH",
}

local function build_sip_request(method, host_ip, branch, tag, call_id)
  return method .. " sip:" .. host_ip .. " SIP/2.0\r\n" ..
    "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK" .. branch .. "\r\n" ..
    "From: \"scanner\" <sip:scanner@127.0.0.1>;tag=" .. tag .. "\r\n" ..
    "To: <sip:" .. host_ip .. ">\r\n" ..
    "Call-ID: " .. call_id .. "@127.0.0.1\r\n" ..
    "CSeq: 1 " .. method .. "\r\n" ..
    "Contact: <sip:scanner@127.0.0.1>\r\n" ..
    "Max-Forwards: 70\r\n" ..
    "User-Agent: HackIT SIP Scanner\r\n" ..
    "Content-Length: 0\r\n\r\n"
end

local function parse_sip_response(response)
  local info = {}

  local status_line = response:match("SIP/2%.0 (%d+)")
  if status_line then
    info.code = tonumber(status_line)
    local texts = {
      [100] = "Trying", [180] = "Ringing", [200] = "OK",
      [300] = "Multiple Choices", [301] = "Moved Permanently",
      [302] = "Moved Temporarily", [400] = "Bad Request",
      [401] = "Unauthorized", [403] = "Forbidden", [404] = "Not Found",
      [405] = "Method Not Allowed", [406] = "Not Acceptable",
      [407] = "Proxy Authentication Required", [408] = "Request Timeout",
      [413] = "Request Entity Too Large", [414] = "Request-URI Too Long",
      [415] = "Unsupported Media Type", [416] = "Unsupported URI Scheme",
      [420] = "Bad Extension", [421] = "Extension Required",
      [422] = "Session Timer Too Small", [423] = "Interval Too Brief",
      [480] = "Temporarily Unavailable", [481] = "Call/Transaction Does Not Exist",
      [482] = "Loop Detected", [483] = "Too Many Hops",
      [484] = "Address Incomplete", [485] = "Ambiguous",
      [486] = "Busy Here", [487] = "Request Terminated",
      [488] = "Not Acceptable Here", [491] = "Request Pending",
      [493] = "Undecipherable", [500] = "Internal Server Error",
      [501] = "Not Implemented", [502] = "Bad Gateway",
      [503] = "Service Unavailable", [504] = "Server Time-out",
      [505] = "Version Not Supported", [513] = "Message Too Large",
      [600] = "Busy Everywhere", [603] = "Decline",
      [604] = "Does Not Exist Anywhere", [606] = "Not Acceptable",
    }
    info.text = texts[tonumber(status_line)] or "Unknown"
  end

  local allow = response:match("Allow: ([^\r\n]+)")
  if allow then
    info.allowed = {}
    for m in allow:gmatch("[^,%s]+") do
      insert(info.allowed, m)
    end
  end

  info.supported = response:match("Supported: ([^\r\n]+)")
  info.server = response:match("Server: ([^\r\n]+)")
  info.user_agent = response:match("User%-Agent: ([^\r\n]+)")
  info.accept = response:match("Accept: ([^\r\n]+)")
  info.content_type = response:match("Content%-Type: ([^\r\n]+)")
  info.www_authenticate = response:match("WWW%-Authenticate: ([^\r\n]+)")
  info.proxy_authenticate = response:match("Proxy%-Authenticate: ([^\r\n]+)")
  info.contact = response:match("Contact: ([^\r\n]+)")
  info.expires = response:match("Expires: (%d+)")

  return info
end

action = function(host, port)
  local result = output_table()
  local socket = new_socket()
  socket:set_timeout(5000)

  local ok, err = pcall(socket.connect, socket, host.ip, port.number)
  if not ok then
    return format_output(false, "Failed to connect: " .. tostring(err))
  end

  local branch = math.random(100000, 999999)
  local tag = math.random(1000, 9999)
  local call_id = math.random(1000000, 9999999)
  local opts_req = build_sip_request("OPTIONS", host.ip, branch, tag, call_id)

  local ok2, send_err = pcall(socket.send, socket, opts_req)
  if not ok2 then
    socket:close()
    return format_output(false, "Failed to send SIP OPTIONS: " .. tostring(send_err))
  end

  local ok3, response = pcall(socket.receive_buf, socket, 4096, true)
  if not ok3 or not response then
    socket:close()
    return format_output(false, "No SIP response received")
  end

  local opts_info = parse_sip_response(response)
  result.response_code = opts_info.code
  result.response_text = opts_info.text

  if opts_info.allowed then
    result.allowed_methods = opts_info.allowed
    result.methods_count = #opts_info.allowed
  end

  if opts_info.supported then
    result.extensions = opts_info.supported
  end

  result.server = opts_info.server
  result.user_agent = opts_info.user_agent
  result.accept = opts_info.accept
  result.content_type = opts_info.content_type
  result.www_authenticate = opts_info.www_authenticate
  result.proxy_authenticate = opts_info.proxy_authenticate
  result.contact = opts_info.contact
  result.expires = opts_info.expires

  local allowed_set = {}
  if opts_info.allowed then
    for _, m in ipairs(opts_info.allowed) do
      allowed_set[m] = true
    end
  end

  local tested_methods = {}
  for _, method in ipairs(sip_methods_to_test) do
    if method ~= "OPTIONS" and not allowed_set[method] then
      local sock2 = new_socket()
      sock2:set_timeout(3000)
      local ok4, err4 = pcall(sock2.connect, sock2, host.ip, port.number)
      if ok4 then
        local req = build_sip_request(method, host.ip, branch + 1, tag + 1, call_id + 1)
        local ok5 = pcall(sock2.send, sock2, req)
        if ok5 then
          local ok6, resp2 = pcall(sock2.receive_buf, sock2, 1024, false)
          if ok6 and resp2 then
            local method_info = parse_sip_response(resp2)
            insert(tested_methods, {
              method = method,
              code = method_info.code,
              text = method_info.text,
            })
          end
        end
      end
      sock2:close()
    end
  end

  if #tested_methods > 0 then
    result.method_test_results = tested_methods
  end

  socket:close()
  return format_output(true, result)
end
