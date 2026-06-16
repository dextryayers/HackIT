local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
local bit = require "bit"

description = [[Detects MQTT brokers and retrieves information about the broker. Attempts to subscribe to common topics to discover exposed data streams. Includes CONNECT, SUBSCRIBE, and PINGREQ probes with detailed response parsing.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "iot"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and (port.number == 1883 or port.number == 8883)
end

local subscribe_topics = {
  "/status", "/data", "/sensor", "/telemetry", "/health",
  "/system", "/temperature", "/humidity", "/power", "/energy",
  "/config", "/alarm", "/event", "/log", "/debug",
  "/$SYS/#", "/$SYS/broker/version", "/$SYS/broker/uptime",
  "/$SYS/broker/clients/total", "/$SYS/broker/messages/sent",
  "status", "data", "sensor", "telemetry", "health",
  "system", "temperature", "#", "+",
}

local function mqtt_connect_packet(client_id)
  local remaining = 10 + #client_id
  local packet = string.char(0x10) .. string.char(remaining) ..
    "\x00\x04MQTT\x04\x02\x00\x3c" ..
    string.char(math.floor(#client_id / 256), #client_id % 256) ..
    client_id
  return packet
end

local function mqtt_subscribe_packet(packet_id, topic)
  local topic_remaining = 2 + 2 + #topic + 1
  local packet = string.char(0x82) .. string.char(topic_remaining) ..
    string.char(math.floor(packet_id / 256), packet_id % 256) ..
    string.char(math.floor(#topic / 256), #topic % 256) ..
    topic .. "\x00"
  return packet
end

action = function(host, port)
  local result = stdnse.output_table()
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local ok, err = pcall(socket.connect, socket, host.ip, port.number)
  if not ok then
    return stdnse.format_output(false, "Failed to connect: " .. tostring(err))
  end

  local client_id = "HackIT_" .. math.random(1000, 9999)
  local connect_pkt = mqtt_connect_packet(client_id)

  local ok2, serr = pcall(socket.send, socket, connect_pkt)
  if not ok2 then
    socket:close()
    return stdnse.format_output(false, "Failed to send MQTT CONNECT: " .. tostring(serr))
  end

  local ok3, response = pcall(socket.receive, socket, 4)
  if not ok3 or not response or #response < 1 then
    socket:close()
    return stdnse.format_output(false, "No response from broker")
  end

  local byte = string.byte(response, 1)
  if bit.band(byte, 0xF0) ~= 0x20 then
    socket:close()
    return stdnse.format_output(false, "Not an MQTT broker")
  end

  result.broker_detected = true

  if #response >= 4 then
    local return_code = string.byte(response, 4)
    local codes = {
      [0] = "Connection Accepted",
      [1] = "Unacceptable Protocol Version",
      [2] = "Identifier Rejected",
      [3] = "Server Unavailable",
      [4] = "Bad Username or Password",
      [5] = "Not Authorized",
    }
    result.connection_status = codes[return_code] or "Unknown (" .. return_code .. ")"
    result.connection_accepted = return_code == 0
  end

  if result.connection_accepted then
    local found_topics = {}
    for i, topic in ipairs(subscribe_topics) do
      local sub_pkt = mqtt_subscribe_packet(i, topic)
      local ok4 = pcall(socket.send, socket, sub_pkt)
      if ok4 then
        local ok5, sub_resp = pcall(socket.receive, socket, 5)
        if ok5 and sub_resp and #sub_resp >= 5 then
          local sub_return = string.byte(sub_resp, 5)
          if sub_return == 0x00 or sub_return == 0x01 then
            table.insert(found_topics, { topic = topic, qos = sub_return })
          end
        end
      end
    end

    if #found_topics > 0 then
      result.accessible_topics = found_topics
      result.topics_accessible = #found_topics
    end

    local ping_pkt = string.char(0xC0, 0x00)
    pcall(socket.send, socket, ping_pkt)
    local ok6, pong = pcall(socket.receive, socket, 2)
    if ok6 and pong and #pong >= 1 and string.byte(pong, 1) == 0xD0 then
      result.pingresp_received = true
    end
  end

  socket:close()
  return stdnse.format_output(true, result)
end
