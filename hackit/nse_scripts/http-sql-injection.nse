local http = require "http"
local stdnse = require "stdnse"
local nmap = require "nmap"
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

description = [[Injects common SQLi payloads into query parameters and looks for SQL error messages in the response.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local function build_payloads(host)
    local items = {"'", "\"", "1' OR '1'='1", "1\" OR \"1\"=\"1", "' UNION SELECT 1--", "' OR 1=1--"
    }
    return items
end
    local error_patterns = {
        "SQL syntax.*MySQL", "Warning.*mysql_.*", "MySqli", "SQLite",
        "ORA-[0-9]{5}", "Oracle.*Driver", "PostgreSQL.*ERROR",
        "Microsoft.*ODBC", "Driver.*SQL Server", "Unclosed quotation mark",
        "You have an error in your SQL", "Syntax error in SQL",
        "Division by zero", "Unknown column", "Table.*doesn't exist"
    }
    local test_params = {"id", "page", "cat", "category", "product", "user", "pid"}
    local results = {}
    for _, param in ipairs(test_params) do
        for _, payload in ipairs(build_payloads(host)) do
            local url = "/?" .. param .. "=" .. payload
            local response = http.get(host, port, url)
            if response and response.body then
                for _, pattern in ipairs(error_patterns) do
                    if response.find(body, pattern) then
                        insert(results, "SQL error via " .. param .. " with payload: " .. payload)
                        break
                    end
                end
            end
            if #results >= 5 then break end
        end
        if #results >= 5 then break end
    end
    if #results == 0 then
        return format_output(false, "No SQL error signatures detected")
    end
    return format_output(true, concat(results, "\n"))
end
