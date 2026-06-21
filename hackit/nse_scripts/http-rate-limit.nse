local stdnse = require "stdnse"
local http = require "http"
local string = require "string"
local os = require "os"
local math = require "math"
local nmap = require "nmap"
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

description = [[Detects HTTP rate limiting by sending rapid successive requests. Analyzes response codes, Retry-After headers, and response time patterns to identify rate limiting, WAF blocking, and request throttling.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open" and
        (port.service == "http" or port.service == "https")
end

local request_counts = { 10, 25, 50, 100 }
local delay_values = { 0, 10, 50, 100 }

local limit_response_codes = {
    [429] = "Rate limit (HTTP 429)",
    [503] = "Service Unavailable (possible rate limit)",
    [403] = "Forbidden (possible WAF blocking)",
    [420] = "Enhance Your Calm (Twitter rate limit)",
    [509] = "Bandwidth Limit Exceeded",
}

action = function(host, port)
    local result = output_table()
    local all_tests = {}

    for _, count in ipairs(request_counts) do
        for _, delay in ipairs(delay_values) do
            local statuses = {}
            local resp_times = {}
            local retry_after = nil
            local start_time = os.time()

            for i = 1, count do
                local req_start = os.clock()
                local ok, response = pcall(http.get, host, port, "/", { timeout = 5000 })
                if ok and response and response.status then
                    insert(statuses, response.status)
                    insert(resp_times, os.clock() - req_start)

                    if not retry_after and response.header and response.header["retry-after"] then
                        retry_after = response.header["retry-after"]
                    end
                end
                if delay > 0 then
                    os.sleep(delay / 1000)
                end
            end

            local total_time = os.time() - start_time
            local status_counts = {}
            for _, s in ipairs(statuses) do
                status_counts[s] = (status_counts[s] or 0) + 1
            end

            local limited = false
            local limit_info = {}
            for code, desc in pairs(limit_response_codes) do
                if status_counts[code] then
                    limited = true
                    insert(limit_info, {
                        code = code,
                        description = desc,
                        count = status_counts[code],
                        percentage = math.floor(status_counts[code] / #statuses * 100),
                    })
                end
            end

            if not limited then
                local stable = true
                for i = 2, #statuses do
                    if statuses[i] ~= statuses[1] then
                        stable = false
                        break
                    end
                end
                if not stable then
                    limited = true
                    insert(limit_info, {
                        code = 0,
                        description = "Varying status codes (possible conditional limiting)",
                    })
                end
            end

            local avg_resp_time = 0
            if #resp_times > 0 then
                local total = 0
                for _, t in ipairs(resp_times) do
                    total = total + t
                end
                avg_resp_time = total / #resp_times
            end

            insert(all_tests, {
                request_count = count,
                delay_ms = delay,
                duration_seconds = total_time,
                limited = limited,
                limit_indicators = limit_info,
                status_distribution = status_counts,
                avg_response_time = math.floor(avg_resp_time * 1000) .. "ms",
                retry_after = retry_after,
                first_request_status = statuses[1],
            })
        end
    end

    local any_limited = false
    for _, test in ipairs(all_tests) do
        if test.limited then
            any_limited = true
            break
        end
    end

    result.rate_limiting_detected = any_limited
    result.tests = all_tests
    result.test_scenarios = #all_tests

    local min_trigger = nil
    for _, test in ipairs(all_tests) do
        if test.limited and (not min_trigger or test.request_count < min_trigger) then
            min_trigger = test.request_count
        end
    end
    if min_trigger then
        result.min_requests_to_trigger = min_trigger
    end

    return format_output(true, result)
end
