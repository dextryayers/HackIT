local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local http = require "http"



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

description = [[
Explores the Docker Registry v2 API to enumerate repositories, tags, and
manifests. Checks if the registry is accessible without authentication and
attempts to list available container images and their tags.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(5000, "http")

action = function(host, port)
    local result = {}
    local api_endpoints = {
        {"/v2/", "Docker Registry v2 API"},
        {"/v2/_catalog", "Repository catalog"},
    }
    for _, ep in ipairs(api_endpoints) do
        local response = http.get(host, port, ep[1])
        if response and response.status then
            if response.status == 200 then
                insert(result, (ep[2] .. " accessible (status %d)"):format(response.status))
                if ep[1] == "/v2/_catalog" and response.body then
                    local repos = response.match(body, '"repositories"%s*:%s*%[([^]]+)%]')
                    if repos then
                        for repo in gmatch(repos, '"([^"]+)"') do
                            insert(result, "  Repository: " .. repo)
                            local tag_resp = http.get(host, port, "/v2/" .. repo .. "/tags/list")
                            if tag_resp and tag_resp.status == 200 and tag_resp.body then
                                local tags = tag_resp.match(body, '"tags"%s*:%s*%[([^]]+)%]')
                                if tags then
                                    for tag in gmatch(tags, '"([^"]+)"') do
                                        insert(result, "    Tag: " .. tag)
                                    end
                                end
                            end
                        end
                    end
                end
            elseif response.status == 401 or response.status == 403 then
                insert(result, (ep[2] .. " requires authentication (status %d)"):format(response.status))
            end
        end
    end
    if #result == 0 then
        insert(result, "Docker Registry API not detected")
    end
    return format_output(true, result)
end
