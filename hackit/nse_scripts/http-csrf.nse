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

description = [[Scans forms in the target page for CSRF tokens (hidden input fields with anti-forgery names).]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local response = http.get(host, port, "/")
    if not response or not response.body then
        return format_output(false, "No response body")
    end
    local forms = {}
    for form in response.gmatch(body, "<form.-</form>") do
        insert(forms, form)
    end
    if #forms == 0 then
        return format_output(false, "No forms found on page")
    end
    local results = {}
    for i, form in ipairs(forms) do
        local action_attr = match(form, 'action%s*=%s*["\'](.-)["\']') or "(no action)"
        local has_csrf = false
        for token_pattern in pairs({["csrf"] = true, ["token"] = true, ["_token"] = true, ["csrf_token"] = true, ["authenticity_token"] = true, ["__csrf"] = true, ["nonce"] = true}) do
            if match(form, 'type%s*=%s*["\']hidden["\']') and (match(form, 'name%s*=%s*["\'].-csrf') or match(form, 'name%s*=%s*["\'].-token') or match(form, 'name%s*=%s*["\'].-nonce')) then
                has_csrf = true
                break
            end
        end
        if not has_csrf then
            has_csrf = match(form, 'name%s*=%s*["\']_csrf') and true
        end
        local status = has_csrf and "CSRF token present" or "NO CSRF token"
        insert(results, "Form #" .. i .. " (action=" .. action_attr .. "): " .. status)
    end
    return format_output(true, concat(results, "\n"))
end
