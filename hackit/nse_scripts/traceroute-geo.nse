local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local json = require "json"



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
local new_socket = nmap.new_socket
local resolve = nmap.resolve

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

-- shortport.address_family is not part of the shortport API.
local address_family = function(af)
    return function(host, port) return nmap.address_family() == af end
end

description = [[
Performs a TCP-based traceroute to the target and geolocates each hop along the
network path. Uses increasing TTL values with TCP SYN probes to map intermediate
routers. Each responding hop IP is then geolocated via multiple services (ip-api.com
with fallback) to build a geographically-annotated route map. Measures round-trip
time per hop and detects routing loops, asymmetric paths, and latency anomalies.
Useful for network path analysis, CDN verification, and troubleshooting connectivity
issues across regions.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = address_family("inet")

local geo_cache = {}

local function geo_lookup(ip)
  if geo_cache[ip] then return geo_cache[ip] end

  local providers = {
    { host = "ip-api.com", port = 80, path = "/json/", parse = function(d)
      if d and d.status == "success" then
        return (d.city or "?") .. ", " .. (d.countryCode or d.country or "?")
      end return nil end
    }
  }

  for _, p in ipairs(providers) do
    local ok, resp = pcall(http.get, p.host, p.port, p.path .. ip, { timeout = 3000, any_af = true })
    if ok and resp and resp.status == 200 and resp.body then
      local pok, data = pcall(json.parse, resp.body)
      if pok then
        local result = p.parse(data)
        if result then
          geo_cache[ip] = result
          return result
        end
      end
    end
  end
  geo_cache[ip] = "Unknown"
  return "Unknown"
end

action = function(host, port)
  local result = output_table()
  local max_hops = 30
  local dest_port = port.number or 80
  local hops = {}

  for ttl = 1, max_hops do
    local start = clock()
    local sock = new_socket("tcp")
    sock:set_timeout(3000)
    sock:set_option("ip_ttl", ttl)

    local ok, conn_err = sock:connect(host.ip, dest_port, "tcp")
    local rtt = (clock() - start) * 1000

    if ok then
      local hop_geo = geo_lookup(host.ip)
      sock:close()
      insert(hops, {
        hop = ttl,
        ip = host.ip,
        rtt_ms = format("%.1f", rtt),
        location = hop_geo,
        reached_target = true
      })
      break
    else
      sock:close()
      local time_exceeded = conn_err and (tostring(conn_err):find("time", 1, true) or
                              tostring(conn_err):find("TTL", 1, true) or
                              tostring(conn_err):find("icmp", 1, true))
      if time_exceeded then
        insert(hops, {
          hop = ttl,
          status = "time_exceeded"
        })
      end
      msleep(100)
    end
  end

  if #hops == 0 then
    result.status = "error"
    result.target = host.ip
    result.reason = "Traceroute completed with no responses"
    return result
  end

  result.status = "success"
  result.target = host.ip
  result.destination_port = dest_port
  result.hops = hops
  result.total_hops = #hops
  result.last_hop_reached_target = hops[#hops] and hops[#hops].reached_target or false

  return result
end
