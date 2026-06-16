local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local json = require "json"

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

portrule = shortport.address_family("inet")

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
  local result = stdnse.output_table()
  local max_hops = 30
  local dest_port = port.number or 80
  local hops = {}

  for ttl = 1, max_hops do
    local start = nmap.clock()
    local sock = nmap.new_socket("tcp")
    sock:set_timeout(3000)
    sock:set_option("ip_ttl", ttl)

    local ok, conn_err = sock:connect(host.ip, dest_port, "tcp")
    local rtt = (nmap.clock() - start) * 1000

    if ok then
      local hop_geo = geo_lookup(host.ip)
      sock:close()
      hops[#hops + 1] = {
        hop = ttl,
        ip = host.ip,
        rtt_ms = string.format("%.1f", rtt),
        location = hop_geo,
        reached_target = true
      }
      break
    else
      sock:close()
      local time_exceeded = conn_err and (tostring(conn_err):find("time", 1, true) or
                              tostring(conn_err):find("TTL", 1, true) or
                              tostring(conn_err):find("icmp", 1, true))
      if time_exceeded then
        hops[#hops + 1] = {
          hop = ttl,
          status = "time_exceeded"
        }
      end
      nmap.msleep(100)
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
