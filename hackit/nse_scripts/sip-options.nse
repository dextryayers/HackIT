local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
local os = require "os"
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

description = [[Performs a SIP OPTIONS scan to discover SIP servers, check their status, determine media capabilities and codec support, and extract security and authentication requirements.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "voip"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and (port.number == 5060 or port.number == 5061)
end

local media_types = {
  "application/sdp", "application/isup", "application/dtmf",
  "application/t140", "application/media_control+xml",
  "text/plain",
}

local function build_options_request(host_ip, port_num, accept)
  local accept_hdr = ""
  if accept then
    accept_hdr = "Accept: " .. accept .. "\r\n"
  end
  return "OPTIONS sip:" .. host_ip .. ":" .. port_num .. " SIP/2.0\r\n" ..
    "Via: SIP/2.0/UDP " .. host_ip .. ":" .. port_num .. ";branch=z9hG4bK" .. os.time() .. "\r\n" ..
    "Max-Forwards: 70\r\n" ..
    "To: <sip:test@" .. host_ip .. ">\r\n" ..
    "From: \"Scanner\" <sip:scanner@" .. host_ip .. ">;tag=" .. math.random(10000, 99999) .. "\r\n" ..
    "Call-ID: " .. os.time() .. "." .. math.random(1000, 9999) .. "@" .. host_ip .. "\r\n" ..
    "CSeq: 1 OPTIONS\r\n" ..
    "Contact: <sip:scanner@" .. host_ip .. ">\r\n" ..
    accept_hdr ..
    "Content-Length: 0\r\n\r\n"
end

local status_reasons = {
  [100] = "Trying", [180] = "Ringing", [183] = "Session Progress",
  [200] = "OK", [300] = "Multiple Choices", [301] = "Moved Permanently",
  [302] = "Moved Temporarily", [305] = "Use Proxy",
  [380] = "Alternative Service", [400] = "Bad Request",
  [401] = "Unauthorized", [402] = "Payment Required",
  [403] = "Forbidden", [404] = "Not Found", [405] = "Method Not Allowed",
  [406] = "Not Acceptable", [407] = "Proxy Authentication Required",
  [408] = "Request Timeout", [410] = "Gone",
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

action = function(host, port)
  local result = output_table()
  local socket = new_socket()
  socket:set_timeout(5000)

  local ok, err = pcall(socket.connect, socket, host.ip, port.number)
  if not ok then
    return format_output(false, "Failed to connect: " .. tostring(err))
  end

  local req = build_options_request(host.ip, port.number)
  local ok2, serr = pcall(socket.send, socket, req)
  if not ok2 then
    socket:close()
    return format_output(false, "Failed to send OPTIONS: " .. tostring(serr))
  end

  local ok3, response = pcall(socket.receive_buf, socket, 4096, true)
  socket:close()

  if not ok3 or not response then
    return format_output(false, "No response received")
  end

  local sip_version = match(response, "(SIP/2%.0)")
  if not sip_version then
    return format_output(false, "Not a SIP server")
  end

  result.sip_detected = true
  result.sip_version = sip_version

  local code = match(response, "SIP/2%.0 (%d+)")
  if code then
    result.status = tonumber(code)
    result.reason = status_reasons[tonumber(code)] or "Unknown"
  end

  result.accepts_sdp = match(response, "application/sdp") and true or nil
  result.accepts_isup = match(response, "application/isup") and true or nil

  result.accept_header = match(response, "Accept: ([^\r\n]+)")
  result.user_agent = match(response, "User%-Agent: ([^\r\n]+)")
  result.server = match(response, "Server: ([^\r\n]+)")
  result.allow = match(response, "Allow: ([^\r\n]+)")
  result.supported = match(response, "Supported: ([^\r\n]+)")
  result.contact = match(response, "Contact: ([^\r\n]+)")
  result.www_auth = match(response, "WWW%-Authenticate: ([^\r\n]+)")
  result.proxy_auth = match(response, "Proxy%-Authenticate: ([^\r\n]+)")
  result.content_length = match(response, "Content%-Length: (%d+)")
  result.expires = match(response, "Expires: (%d+)")

  for _, mt in ipairs(media_types) do
    if find(response, mt) then
      if not result.supported_media then result.supported_media = {} end
      insert(result.supported_media, mt)
    end
  end

  if result.www_auth or result.proxy_auth then
    result.authentication_required = true
  end

  local body_match = match(response, "\r\n\r\n(.+)")
  if body_match and #body_match > 0 then
    result.response_body = "present (" .. #body_match .. " bytes)"
    if find(body_match, "v=0") then
      result.sdp_present = true
    end
  end

  return format_output(true, result)
end
