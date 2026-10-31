local nmap = require "nmap"
local stdnse = require "stdnse"
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

description = [[
Enumerates MQTT broker information and topics by connecting to the broker
and subscribing to system topics. Extracts broker version, client IDs,
and available topics from $SYS hierarchy.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(1883, "mqtt")

local function mqtt_connect()
    local packet = char(0x10, 0x00)
    local protocol = "MQTT"
    local payload = char(0x00, 0x04) .. protocol
        .. char(0x04, 0x02, 0x00, 0x3c)
        .. char(0x00, 0x07) .. "nmap_nse"
    payload = char(0x10, #payload) .. sub(payload, 2)
    return payload
end

local function mqtt_subscribe(topic, id)
    local topic_enc = char(0x00, #topic) .. topic
    local payload = char(0x82, 0x00)
        .. char(0x00, id)
        .. topic_enc
        .. char(0x00)
    payload = char(0x82, #payload - 1) .. sub(payload, 2)
    return payload
end

action = function(host, port)
    local result = {}
    local socket = new_socket()
    socket:set_timeout(5000)
    local status, err = socket:connect(host, port)
    if not status then
        return format_output(false, "Could not connect to MQTT broker: " .. tostring(err))
    end
    socket:send(mqtt_connect())
    local status, response = socket:receive_bytes(1)
    if not status then
        socket:close()
        return format_output(false, "No CONNACK response")
    end
    if byte(response, 1) == 0x20 then
        insert(result, "MQTT broker connection established")
        local return_code = byte(response, 5)
        if return_code == 0 then
            insert(result, "Connection accepted (no auth required)")
        else
            insert(result, ("Connection refused (code %d)"):format(return_code))
            socket:close()
            return format_output(true, result)
        end
    end
    local sys_topics = {"$SYS/#", "$SYS/broker/version", "$SYS/broker/client_id",
        "$SYS/broker/uptime", "$SYS/broker/messages/sent", "$SYS/broker/bytes/received"}
    for i, topic in ipairs(sys_topics) do
        socket:send(mqtt_subscribe(topic, i))
        local status, suback = socket:receive_bytes(1)
        if status and byte(suback, 1) == 0x90 then
            insert(result, ("Subscribed to %s"):format(topic))
            local status, pub = socket:receive_bytes(1)
            if status and byte(pub, 1) == 0x30 then
                local tlen = byte(pub, 3) * 256 + byte(pub, 4)
                local topic_name = sub(pub, 5, 4 + tlen)
                local payload = sub(pub, 5 + tlen)
                insert(result, ("  %s: %s"):format(topic_name, payload))
            end
        end
    end
    socket:close()
    return format_output(true, result)
end
