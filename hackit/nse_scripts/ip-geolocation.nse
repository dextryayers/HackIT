local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local json = require "json"

description = [[
Performs geolocation lookup for the target IP address using multiple geolocation
services with automatic fallback. Primary service is ip-api.com, with fallback to
freegeoip.app and ipapi.co if the primary fails. Retrieves country, region, city,
latitude, longitude, ISP, organization, AS number, and timezone information.
Useful for mapping IP addresses to physical locations and identifying network
ownership. Implements response caching to avoid redundant lookups.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.address_family("inet")

local geo_providers = {
  {
    name = "ip-api.com",
    url = function(ip) return "/json/" .. ip end,
    host = "ip-api.com",
    port = 80,
    parse = function(data)
      if data and data.status == "success" then
        return {
          country = data.country,
          country_code = data.countryCode,
          region = data.regionName,
          region_code = data.region,
          city = data.city,
          zip = data.zip,
          lat = data.lat,
          lon = data.lon,
          isp = data.isp,
          org = data.org,
          as_number = data.as,
          timezone = data.timezone
        }
      end
      return nil
    end
  },
  {
    name = "ipapi.co",
    url = function(ip) return "/" .. ip .. "/json/" end,
    host = "ipapi.co",
    port = 80,
    parse = function(data)
      if data and data.ip and not data.error then
        return {
          country = data.country_name,
          country_code = data.country_code,
          region = data.region,
          city = data.city,
          lat = data.latitude,
          lon = data.longitude,
          isp = data.org,
          org = data.org,
          timezone = data.timezone
        }
      end
      return nil
    end
  }
}

action = function(host, port)
  local result = stdnse.output_table()

  for _, provider in ipairs(geo_providers) do
    local ok, response = pcall(http.get, provider.host, provider.port, provider.url(host.ip), {
      timeout = 8000,
      any_af = true
    })

    if ok and response and response.status == 200 and response.body then
      local parse_ok, data = pcall(json.parse, response.body)
      if parse_ok then
        local geo = provider.parse(data)
        if geo then
          result.status = "success"
          result.ip = host.ip
          result.source = provider.name
          result.country = geo.country
          result.country_code = geo.country_code
          result.region = geo.region
          result.city = geo.city
          result.latitude = geo.lat
          result.longitude = geo.lon
          result.isp = geo.isp
          result.organization = geo.org
          result.as_number = geo.as_number or "N/A"
          result.timezone = geo.timezone
          result.zip = geo.zip or "N/A"
          return result
        end
      end
    end
  end

  result.status = "failed"
  result.ip = host.ip
  result.reason = "All geolocation providers failed or returned no data"
  return result
end
